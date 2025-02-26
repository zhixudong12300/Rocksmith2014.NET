module Rocksmith2014.XML.Processing.PhraseMover

open Rocksmith2014.XML
open Rocksmith2014.XML.Extensions
open System
open System.Globalization

let private getMoveBy phraseTime (phraseToMove: Phrase) =
    let number = phraseToMove.Name.AsSpan("mover".Length)

    match Int32.TryParse(number, NumberStyles.Integer, NumberFormatInfo.InvariantInfo) with
    | true, moveBy ->
        moveBy
    | false, _ ->
        failwith $"Unable to parse value for 'moveR' phrase at {Utils.timeToString phraseTime}"

/// Moves phrases that have a special name "mover" (move right).
let improve (arrangement: InstrumentalArrangement) =
    arrangement.Phrases
    |> Seq.filter (fun p -> String.startsWith "mover" p.Name)
    |> Seq.iter (fun phraseToMove ->
        let phraseId = arrangement.Phrases.IndexOf(phraseToMove)

        arrangement.PhraseIterations
        |> Seq.filter (fun pi -> pi.PhraseId = phraseId)
        |> Seq.iter (fun iterationToMove ->
            let phraseTime = iterationToMove.Time
            let movetoTime =
                let moveBy = getMoveBy phraseTime phraseToMove
                let level = arrangement.Levels.[int phraseToMove.MaxDifficulty]
                Utils.findTimeOfNthNoteFrom level phraseTime moveBy

            // Check if anchor(s) should be moved
            arrangement.Levels
            |> Seq.takeWhile (fun level -> level.Difficulty <= sbyte phraseToMove.MaxDifficulty)
            |> Seq.iter (fun level ->
                let anchors = level.Anchors
                let originalAnchorIndex = anchors.FindIndexByTime(phraseTime)
                let movetoAnchorIndex = anchors.FindIndexByTime(movetoTime)

                // If there is an anchor at the original position, but not at the new position, move it
                if originalAnchorIndex <> -1 && movetoAnchorIndex = -1 then
                    let originalAnchor = anchors.[originalAnchorIndex]
                    anchors.InsertByTime(Anchor(originalAnchor.Fret, movetoTime, originalAnchor.Width))

                    // Remove anchor at original phrase position if no note or chord present
                    if level.Notes.FindIndexByTime(phraseTime) = -1 && level.Chords.FindIndexByTime(phraseTime) = -1 then
                        anchors.RemoveAt(originalAnchorIndex))

            // Move phrase iteration
            iterationToMove.Time <- movetoTime

            // Move section (if present)
            let sectionToMove = arrangement.Sections.FindByTime(phraseTime)
            if notNull sectionToMove then
                sectionToMove.Time <- movetoTime))
