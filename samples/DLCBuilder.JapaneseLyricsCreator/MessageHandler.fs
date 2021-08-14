module JapaneseLyricsCreator.MessageHandler

open Rocksmith2014.XML

let private isWithinBounds array index1 index2 =
    array
    |> Array.tryItem index1
    |> Option.exists (fun subArray -> index2 < Array.length subArray - 1)

let update lyricsEditorState msg =
    match msg with
    | SaveLyricsToFile targetPath ->
        let vocals =
            lyricsEditorState.MatchedLines
            |> Array.collect (fun line ->
                line
                |> Array.map (fun matched ->
                    let vocal = Vocal(matched.Vocal)
                    matched.Japanese
                    |> Option.iter (fun jp ->
                        vocal.Lyric <-
                            if matched.Vocal.Lyric.EndsWith "+" && not <| jp.EndsWith "+" then
                                jp + "+"
                            else
                                jp)
                    vocal))
            |> ResizeArray

        Vocals.Save(targetPath, vocals)
        lyricsEditorState

    | SetJapaneseLyrics jLyrics ->
        let japaneseLines =
            jLyrics
            |> LyricsTools.hyphenateToSyllableLines
            |> LyricsTools.matchNonJapaneseHyphenation lyricsEditorState.MatchedLines
            |> LyricsTools.applyCombinations lyricsEditorState.CombinedJapanese

        let matchedSyllables =
            lyricsEditorState.MatchedLines
            |> Array.mapi (fun lineNumber line ->
                line
                |> Array.mapi (fun i syllable ->
                    let jp =
                        japaneseLines
                        |> Array.tryItem lineNumber
                        |> Option.bind (Array.tryItem i)

                    { syllable with Japanese = jp }))

        LyricsCreatorState.addUndo lyricsEditorState
        { lyricsEditorState with MatchedLines = matchedSyllables
                                 JapaneseLyrics = jLyrics
                                 JapaneseLines = japaneseLines }

    | CombineJapaneseWithNext location ->
        if not <| isWithinBounds lyricsEditorState.JapaneseLines location.LineNumber location.Index then
            lyricsEditorState
        else
            let combinedJp = location::lyricsEditorState.CombinedJapanese

            let japaneseLines =
                lyricsEditorState.JapaneseLyrics
                |> LyricsTools.hyphenateToSyllableLines
                |> LyricsTools.matchNonJapaneseHyphenation lyricsEditorState.MatchedLines
                |> LyricsTools.applyCombinations combinedJp

            let matchedLines =
                lyricsEditorState.MatchedLines
                |> Array.mapi (fun lineNumber line ->
                    line
                    |> Array.mapi (fun i syllable ->
                        let jp =
                            japaneseLines
                            |> Array.tryItem lineNumber
                            |> Option.bind (Array.tryItem i)

                        { syllable with Japanese = jp }))

            LyricsCreatorState.addUndo lyricsEditorState
            { lyricsEditorState with CombinedJapanese = combinedJp
                                     JapaneseLines = japaneseLines
                                     MatchedLines = matchedLines }

    | CombineSyllableWithNext { Index = index; LineNumber = lineNumber } ->
        if not <| isWithinBounds lyricsEditorState.MatchedLines lineNumber index then
            lyricsEditorState
        else
            let line = lyricsEditorState.MatchedLines.[lineNumber]

            let v = line.[index].Vocal
            let vNext = line.[index + 1].Vocal

            let combinedVocal =
                let lyric =
                    let first = if v.Lyric.EndsWith "-" then v.Lyric.Substring(0, v.Lyric.Length - 1) else v.Lyric
                    first + vNext.Lyric
                Vocal(v.Time, (vNext.Time + vNext.Length) - v.Time, lyric, v.Note)

            let combined = { line.[index] with Vocal = combinedVocal }

            let newSyllables =
                lyricsEditorState.MatchedLines
                |> Array.mapi (fun linei line ->
                    if linei = lineNumber then
                        line
                        |> Array.mapi (fun i x ->
                            if i = index + 1 then
                                None
                            elif i = index then
                                Some combined
                            else
                                Some x)
                        |> Array.choose id
                    else
                        line)

            let matchedSyllables =
                newSyllables
                |> Array.mapi (fun lineNumber line ->
                    line
                    |> Array.mapi (fun i syllable ->
                        let jp =
                            lyricsEditorState.JapaneseLines
                            |> Array.tryItem lineNumber
                            |> Option.bind (Array.tryItem i)

                        { syllable with Japanese = jp }))

            LyricsCreatorState.addUndo lyricsEditorState
            { lyricsEditorState with MatchedLines = matchedSyllables }

    | UndoLyricsChange ->
        LyricsCreatorState.tryUndo lyricsEditorState
