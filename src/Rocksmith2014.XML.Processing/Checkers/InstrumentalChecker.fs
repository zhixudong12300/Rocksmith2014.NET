module Rocksmith2014.XML.Processing.InstrumentalChecker

open Rocksmith2014.XML
open System
open System.Runtime.CompilerServices
open System.Text.RegularExpressions
open Utils

[<IsReadOnly; Struct>]
type private NgSection = { StartTime: int; EndTime: int }

/// Checks for unexpected crowd events between the intro applause start and end events.
let checkCrowdEventPlacement (arrangement: InstrumentalArrangement) =
    let introApplauseStart =
        arrangement.Events
        |> ResizeArray.tryFind (fun e -> e.Code = "E3")

    let applauseEnd =
        arrangement.Events
        |> ResizeArray.tryFind (fun e -> e.Code = "E13")

    let crowdEventRegex = Regex("e[0-2]|E3|D3$")

    match introApplauseStart, applauseEnd with
    | None, _ ->
        List.empty
    | Some start, None ->
        [ issue ApplauseEventWithoutEnd start.Time ]
    | Some start, Some end' ->
        arrangement.Events
        |> Seq.filter (fun ev -> ev.Time > start.Time && ev.Time < end'.Time && crowdEventRegex.IsMatch ev.Code)
        |> Seq.map (fun ev -> issue (EventBetweenIntroApplause ev.Code) ev.Time)
        |> Seq.toList

let private getNoguitarSections (arrangement: InstrumentalArrangement) =
    [| let sections = arrangement.Sections

       for i in 1 .. sections.Count do
           let section = sections.[i - 1]

           let endTime =
               if i = sections.Count then
                   arrangement.MetaData.SongLength
               else
                   sections.[i].Time

           if String.startsWith "noguitar" section.Name then
               { StartTime = section.Time
                 EndTime = endTime } |]

let private isInsideNoguitarSection noGuitarSections (time: int) =
    noGuitarSections
    |> Array.exists (fun x -> time >= x.StartTime && time < x.EndTime)

let private isLinkedToChord (level: Level) (note: Note) =
    level.Chords.Exists(fun c -> 
        c.Time = note.Time + note.Sustain
        && c.HasChordNotes
        && c.ChordNotes.Exists(fun cn -> cn.String = note.String))

let private findNextNote (notes: ResizeArray<Note>) currentIndex (note: Note) =
    let nextIndex =
        if currentIndex = -1 then
            notes.FindIndex(fun n -> n.Time > note.Time && n.String = note.String)
        else
            notes.FindIndex(currentIndex + 1, fun n -> n.String = note.String)

    if nextIndex = -1 then None else Some notes.[nextIndex]

let private checkLinkNext (level: Level) (currentIndex: int) (note: Note) =
    if isLinkedToChord level note then
        Some(issue NoteLinkedToChord note.Time)
    else
        match findNextNote level.Notes currentIndex note with
        | None ->
            Some(issue LinkNextMissingTargetNote note.Time)

        // Check if the next note is at the end of the sustain for this note
        | Some nextNote when nextNote.Time - (note.Time + note.Sustain) > 1 ->
            Some(issue IncorrectLinkNext note.Time)
            
        // Check if the frets match
        | Some nextNote when note.Fret <> nextNote.Fret ->
            let slideTo =
                if note.SlideTo = -1y then
                    note.SlideUnpitchTo
                else
                    note.SlideTo
            
            if slideTo = nextNote.Fret then
                None
            elif slideTo <> -1y then
                Some(issue LinkNextSlideMismatch note.Time)
            else
                Some(issue LinkNextFretMismatch nextNote.Time)

        // Check if the bend values match
        | Some nextNote when note.IsBend ->
            let thisNoteLastBendValue =
                note.BendValues.[note.BendValues.Count - 1].Step

            // If the next note has bend values and the first one is at the same timecode as the note, compare to that bend value
            let nextNoteFirstBendValue =
                if nextNote.IsBend && nextNote.Time = nextNote.BendValues.[0].Time then
                    nextNote.BendValues.[0].Step
                else
                    0f

            if thisNoteLastBendValue <> nextNoteFirstBendValue then
                Some(issue LinkNextBendMismatch nextNote.Time)
            else
                None

        | _ ->
            None

let private isOnToneChange (arr: InstrumentalArrangement) time =
    notNull arr.Tones.Changes
    && arr.Tones.Changes.Exists(fun t -> t.Time = time)

let private isPhraseChangeOnSustain (arr: InstrumentalArrangement) (note: Note) =
    arr.PhraseIterations.Exists(fun pi ->
        pi.Time > note.Time
        && pi.Time <= note.Time + note.Sustain
        && (not <| String.startsWith "mover" arr.Phrases.[pi.PhraseId].Name))

/// Checks the notes in the level for issues.
let checkNotes (arrangement: InstrumentalArrangement) (level: Level) =
    let ngSections = getNoguitarSections arrangement

    [ for i = 0 to level.Notes.Count - 1 do
        let note = level.Notes.[i]
        let time = note.Time

        // Check for notes with LinkNext and unpitched slide
        if note.IsLinkNext && note.IsUnpitchedSlide then
            issue UnpitchedSlideWithLinkNext time

        // Check for phrases placed on a LinkNext note's sustain
        if note.IsLinkNext && isPhraseChangeOnSustain arrangement note then
            issue PhraseChangeOnLinkNextNote time

        // Check for notes with both harmonic and pinch harmonic attributes
        if note.IsHarmonic && note.IsPinchHarmonic then
            issue DoubleHarmonic time

        // Check 23rd and 24th fret notes without ignore attribute
        if note.Fret >= 23y && not note.IsIgnore then
            issue MissingIgnore time

        // Check 7th fret harmonic notes with sustain (and without ignore)
        if not note.IsIgnore && note.Fret = 7y && note.IsHarmonic && note.Sustain > 0 then
            issue SeventhFretHarmonicWithSustain time

        // Check for missing bend values
        if note.IsBend && note.BendValues.FindIndex(fun bv -> bv.Step <> 0.0f) = -1 then
            issue MissingBendValue time

        // Check tone change placement
        if isOnToneChange arrangement time then
            issue ToneChangeOnNote time

        // Check LinkNext issues
        if note.IsLinkNext then
            yield! checkLinkNext level i note |> Option.toList

        // Check for notes inside noguitar sections
        if isInsideNoguitarSection ngSections time then
            issue NoteInsideNoguitarSection time ]

/// Checks the chords in the level for issues.
let checkChords (arrangement: InstrumentalArrangement) (level: Level) =
    let ngSections = getNoguitarSections arrangement

    [ for chord in level.Chords do
        let time = chord.Time

        if chord.HasChordNotes then
            let chordNotes = chord.ChordNotes

            // Check for inconsistent chord note sustains
            if not <| chordNotes.TrueForAll(fun cn -> cn.Sustain = chordNotes.[0].Sustain) then
                issue VaryingChordNoteSustains time

            // Check 7th fret harmonic notes with sustain (and without ignore)
            if not chord.IsIgnore && chordNotes.Exists(fun cn -> cn.Sustain > 0 && cn.Fret = 7y && cn.IsHarmonic) then
                issue SeventhFretHarmonicWithSustain time

            // Check for notes with LinkNext and unpitched slide
            if chordNotes.Exists(fun cn -> cn.IsLinkNext && cn.IsUnpitchedSlide) then
                issue UnpitchedSlideWithLinkNext time

            // Check for notes with both harmonic and pinch harmonic attributes
            if chordNotes.Exists(fun cn -> cn.IsHarmonic && cn.IsPinchHarmonic) then
                issue DoubleHarmonic time

            // Check 23rd and 24th fret chords without ignore attribute
            if chordNotes.TrueForAll(fun cn -> cn.Fret >= 23y) && not chord.IsIgnore then
                issue MissingIgnore time

            // Check for missing bend values
            if chordNotes.Exists(fun cn -> cn.IsBend && cn.BendValues.FindIndex(fun bv -> bv.Step <> 0.0f) = -1) then
                issue MissingBendValue time

            // EOF does not set LinkNext on chords correctly, so check all chords regardless of LinkNext status
            yield!
                chordNotes
                |> Seq.filter (fun cn -> cn.IsLinkNext)
                |> Seq.map (fun cn -> checkLinkNext level -1 cn |> Option.toList)
                |> List.concat

        // Check for chords that have LinkNext, but no LinkNext chord notes
        if chord.IsLinkNext && (not chord.HasChordNotes || chord.ChordNotes.TrueForAll(fun cn -> not cn.IsLinkNext)) then
            issue MissingLinkNextChordNotes time

        // Check tone change placement
        if isOnToneChange arrangement time then
            issue ToneChangeOnNote time

        // Check chords at the end of handshape (no "handshape sustain")
        let handShape =
            level.HandShapes.Find(fun hs ->
                hs.ChordId = chord.ChordId && time >= hs.StartTime && time <= hs.EndTime)

        if notNull handShape && handShape.EndTime - time <= 5 then
            issue ChordAtEndOfHandShape time

        // Check for chords inside noguitar sections
        if isInsideNoguitarSection ngSections time then
            issue NoteInsideNoguitarSection time ]

/// Checks the handshapes in the level for issues.
let checkHandshapes (arrangement: InstrumentalArrangement) (level: Level) =
    let handShapes = level.HandShapes
    let chordTemplates = arrangement.ChordTemplates
    let anchors = level.Anchors

    // Logic to weed out some false positives
    let isSameAnchorWith1stFinger (neighbour: HandShape option) (activeAnchor: Anchor) =
        match neighbour with
        | None ->
            false
        | Some neighbour ->
            let neighbourAnchor = anchors.FindLast(fun a -> a.Time <= neighbour.StartTime)
            let neighbourTemplate = chordTemplates.[int neighbour.ChordId]

            neighbourTemplate.Fingers |> Array.contains 1y && neighbourAnchor = activeAnchor

    [ for i = 0 to handShapes.Count - 1 do
        let handShape = handShapes.[i]
        let previous = handShapes |> ResizeArray.tryItem (i - 1)
        let next = handShapes |> ResizeArray.tryItem (i + 1)

        let activeAnchor = anchors.FindLast(fun a -> a.Time <= handShape.StartTime)
        let chordTemplate = chordTemplates.[int handShape.ChordId]

        // Check only handshapes that do not use the 1st finger
        if not (chordTemplate.Fingers |> Array.contains 1y) && notNull activeAnchor then
            let chordNotOk =
                (chordTemplate.Frets, chordTemplate.Fingers)
                ||> Array.exists2 (fun fret finger -> fret = activeAnchor.Fret && finger <> -1y)

            if chordNotOk && not (isSameAnchorWith1stFinger previous activeAnchor ||
                                  isSameAnchorWith1stFinger next activeAnchor) then
                issue FingeringAnchorMismatch handShape.StartTime
    ]

/// Looks for anchors that are very close to a note but not exactly on a note.
let private findCloseAnchors (level: Level) =
    let pickTimeAndDistance noteTime (anchor: Anchor) =
        let distance = anchor.Time - noteTime 
        if distance <> 0 && abs distance <= 5 then
            Some(anchor.Time, distance)
        else
            None

    let anchorsNearNotes =
        level.Notes
        |> Seq.choose (fun note ->
            Seq.tryPick (pickTimeAndDistance note.Time) level.Anchors)

    let anchorsNearChords =
        level.Chords
        |> Seq.choose (fun chord ->
            Seq.tryPick (pickTimeAndDistance chord.Time) level.Anchors)

    anchorsNearNotes
    |> Seq.append anchorsNearChords
    |> Seq.map (fun (anchorTime, distance) ->
        issue (AnchorNotOnNote distance) anchorTime)

/// Looks for anchors that will break a handshape.
let private findAnchorsInsideHandShapes moverPhraseTimes phraseTimes (level: Level) =
    level.Anchors
    |> Seq.filter (fun anchor ->
        level.HandShapes.Exists(fun hs -> anchor.Time > hs.StartTime && anchor.Time < hs.EndTime)
        && not (Set.contains anchor.Time moverPhraseTimes))
    |> Seq.map (fun anchor ->
        if phraseTimes |> Set.contains anchor.Time then
            issue AnchorInsideHandShapeAtPhraseBoundary anchor.Time
        else
            issue AnchorInsideHandShape anchor.Time)

/// Looks for anchors very close to the end of unpitched slide notes.
let private findUnpitchedSlideAnchors moverPhraseTimes (level: Level) =
    let slideEnds =
        level.Notes
        |> Seq.filter (fun n -> n.IsUnpitchedSlide)
        |> Seq.map (fun n -> n.Time + n.Sustain)
        |> Seq.toArray

    level.Anchors
    |> Seq.filter (fun anchor ->
        Array.exists (fun time -> abs (anchor.Time - time) < 4) slideEnds
        && not (Set.contains anchor.Time moverPhraseTimes))
    |> Seq.map (fun anchor -> issue AnchorCloseToUnpitchedSlide anchor.Time)

/// Checks the anchors in the level for issues.
let checkAnchors (arrangement: InstrumentalArrangement) (level: Level) =
    let moverPhraseTimes =
        arrangement.Phrases
        |> Seq.indexed
        |> Seq.filter (fun (_, phrase) -> String.startsWith "mover" phrase.Name)
        |> Seq.collect (fun (index, _) ->
            arrangement.PhraseIterations.FindAll(fun pi -> pi.PhraseId = index))
        |> Seq.map (fun x -> x.Time)
        |> Set.ofSeq

    let phraseTimes =
        let phraseTimes =
            arrangement.PhraseIterations
            |> Seq.map (fun pi -> pi.Time)

        let sectionTimes =
            arrangement.Sections
            |> Seq.map (fun s -> s.Time)

        phraseTimes
        |> Seq.append sectionTimes
        |> Set.ofSeq

    findCloseAnchors level
    |> Seq.append (findAnchorsInsideHandShapes moverPhraseTimes phraseTimes level)
    |> Seq.append (findUnpitchedSlideAnchors moverPhraseTimes level)
    |> Seq.toList

/// Checks the phrases in the arrangement for issues.
let checkPhrases (arr: InstrumentalArrangement) =
    if arr.PhraseIterations.Count >= 2 then
        let firstNoteTime = Utils.getFirstNoteTime arr

        [ // Check for notes inside the first phrase
          match firstNoteTime with
          | Some firstNoteTime when firstNoteTime < arr.PhraseIterations.[1].Time ->
                issue FirstPhraseNotEmpty firstNoteTime
          | _ ->
                ()

          // Check for missing END phrase
          if not <| arr.Phrases.Exists(fun p -> String.equalsIgnoreCase "END" p.Name) then
            issue NoEndPhrase 0 ]
    else
        List.empty

/// Runs all the checks on the given arrangement.
let runAllChecks (arr: InstrumentalArrangement) =
    let results =
        arr.Levels.ToArray()
        |> Array.Parallel.map (fun level ->
            [ yield! checkNotes arr level
              yield! checkChords arr level
              yield! checkHandshapes arr level
              yield! checkAnchors arr level ])
        |> List.concat

    [ yield! checkCrowdEventPlacement arr
      yield! checkPhrases arr
      yield! results ]
    |> List.distinct
    |> List.sortBy (fun issue -> issue.TimeCode)
