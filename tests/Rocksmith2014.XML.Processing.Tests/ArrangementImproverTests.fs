module Rocksmith2014.XML.Processing.Tests.ArrangementImproverTests

open Expecto
open Rocksmith2014.XML
open Rocksmith2014.XML.Processing

[<Tests>]
let crowdEventTests =
    testList "Arrangement Improver (Crowd Events)" [
        testCase "Creates crowd events" <| fun _ ->
            let notes = ResizeArray(seq { Note(Time = 10000) })
            let level = Level(Notes = notes)
            let arr = InstrumentalArrangement(Levels = ResizeArray(seq { level }))
            arr.MetaData.SongLength <- 120_000

            ArrangementImprover.addCrowdEvents arr

            Expect.isNonEmpty arr.Events "Events were created"

        testCase "No events are created when already present" <| fun _ ->
            let notes = ResizeArray(seq { Note(Time = 10000) })
            let level = Level(Notes = notes)
            let events = ResizeArray(seq { Event("e1", 1000); Event("E3", 10000); Event("D3", 20000) })
            let arr = InstrumentalArrangement(Events = events, Levels = ResizeArray(seq { level }))
            arr.MetaData.SongLength <- 120_000

            ArrangementImprover.addCrowdEvents arr

            Expect.hasLength arr.Events 3 "No new events were created"
    ]

let private f = Array.create 6 -1y

[<Tests>]
let chordNameTests =
    testList "Arrangement Improver (Chord Names)" [
        testCase "Fixes minor chord names" <| fun _ ->
            let c1 = ChordTemplate("Emin", "Emin", f, f)
            let c2 = ChordTemplate("Amin7", "Amin7", f, f)
            let chords = ResizeArray(seq { c1; c2 })
            let arr = InstrumentalArrangement(ChordTemplates = chords)

            ArrangementImprover.processChordNames arr

            Expect.equal c1.Name "Em" "Name was fixed"
            Expect.equal c1.DisplayName "Em" "DisplayName was fixed"
            Expect.isFalse (chords |> Seq.exists(fun c -> c.Name.Contains("min") || c.DisplayName.Contains("min"))) "All chords were fixed"

        testCase "Fixes -arp chord names" <| fun _ ->
            let c = ChordTemplate("E-arp", "E-arp", f, f)
            let chords = ResizeArray(seq { c })
            let arr = InstrumentalArrangement(ChordTemplates = chords)

            ArrangementImprover.processChordNames arr

            Expect.equal c.Name "E" "Name was fixed"
            Expect.equal c.DisplayName "E-arp" "DisplayName was not changed"

        testCase "Fixes -nop chord names" <| fun _ ->
            let c = ChordTemplate("CMaj7-nop", "CMaj7-nop", f, f)
            let chords = ResizeArray(seq { c })
            let arr = InstrumentalArrangement(ChordTemplates = chords)

            ArrangementImprover.processChordNames arr

            Expect.equal c.Name "CMaj7" "Name was fixed"
            Expect.equal c.DisplayName "CMaj7-nop" "DisplayName was not changed"

        testCase "Can convert chords to arpeggios" <| fun _ ->
            let c = ChordTemplate("CminCONV", "CminCONV", f, f)
            let chords = ResizeArray(seq { c })
            let arr = InstrumentalArrangement(ChordTemplates = chords)

            ArrangementImprover.processChordNames arr

            Expect.equal c.Name "Cm" "Name was fixed"
            Expect.equal c.DisplayName "Cm-arp" "DisplayName was fixed"

        testCase "Fixes empty chord names" <| fun _ ->
            let c = ChordTemplate(" ", " ", f, f)
            let chords = ResizeArray(seq { c })
            let arr = InstrumentalArrangement(ChordTemplates = chords)

            ArrangementImprover.processChordNames arr

            Expect.stringHasLength c.Name 0 "Name was fixed"
            Expect.stringHasLength c.DisplayName 0 "DisplayName was fixed"
    ]

[<Tests>]
let beatRemoverTests =
    testList "Arrangement Improver (Beat Remover)" [
        testCase "Removes beats" <| fun _ ->
            let beats = ResizeArray(seq { Ebeat(5000, 1s); Ebeat(6000, 1s); Ebeat(7000, 1s); Ebeat(8000, 1s) })
            let arr = InstrumentalArrangement(Ebeats = beats)
            arr.MetaData.SongLength <- 6000

            ArrangementImprover.removeExtraBeats arr

            Expect.hasLength arr.Ebeats 2 "Two beats were removed"

        testCase "Moves the beat after the end close to it to the end" <| fun _ ->
            let beats = ResizeArray(seq { Ebeat(5000, 1s); Ebeat(6000, 1s); Ebeat(7000, 1s); Ebeat(8000, 1s) })
            let arr = InstrumentalArrangement(Ebeats = beats)
            arr.MetaData.SongLength <- 6900

            ArrangementImprover.removeExtraBeats arr

            Expect.hasLength arr.Ebeats 3 "One beat was removed"
            Expect.equal arr.Ebeats.[2].Time 6900 "Last beat was moved to the correct time"

        testCase "Moves the beat before the end close to it to the end" <| fun _ ->
            let beats = ResizeArray(seq { Ebeat(5000, 1s); Ebeat(6000, 1s); Ebeat(7000, 1s); Ebeat(8000, 1s) })
            let arr = InstrumentalArrangement(Ebeats = beats)
            arr.MetaData.SongLength <- 6100

            ArrangementImprover.removeExtraBeats arr

            Expect.hasLength arr.Ebeats 2 "Two beats were removed"
            Expect.equal arr.Ebeats.[1].Time 6100 "Last beat was moved to the correct time"
    ]

[<Tests>]
let eofFixTests =
    testList "Arrangement Improver (EOF Fixes)" [
        testCase "Fixes LinkNext chords" <| fun _ ->
            let cn = ResizeArray(seq { Note(IsLinkNext = true) })
            let chord = Chord(ChordNotes = cn)
            let chords = ResizeArray(seq { chord })
            let levels = ResizeArray(seq { Level(Chords = chords) })
            let arr = InstrumentalArrangement(Levels = levels)

            EOFFixes.addMissingChordLinkNext arr

            Expect.isTrue chord.IsLinkNext "LinkNext was enabled"

        testCase "Removes incorrect chord note linknexts" <| fun _ ->
            let cn = ResizeArray(seq { Note(IsLinkNext = true) })
            let chords = ResizeArray(seq { Chord(ChordNotes = cn, IsLinkNext = true) })
            let levels = ResizeArray(seq { Level(Chords = chords) })
            let arr = InstrumentalArrangement(Levels = levels)

            EOFFixes.removeInvalidChordNoteLinkNexts arr

            Expect.isFalse cn.[0].IsLinkNext "LinkNext was removed from chord note"

        testCase "Chord note linknext is not removed when there is 1ms gap" <| fun _ ->
            let cn = ResizeArray(seq { Note(String = 0y, Sustain = 499, IsLinkNext = true)
                                       Note(String = 1y, Sustain = 499, IsLinkNext = true) })
            let chords = ResizeArray(seq { Chord(ChordNotes = cn, IsLinkNext = true) })
            let notes = ResizeArray(seq { Note(String = 0y, Time = 500) })
            let levels = ResizeArray(seq { Level(Chords = chords, Notes = notes) })
            let arr = InstrumentalArrangement(Levels = levels)

            EOFFixes.removeInvalidChordNoteLinkNexts arr

            Expect.isTrue cn.[0].IsLinkNext "First chord note has LinkNext"
            Expect.isFalse cn.[1].IsLinkNext "Second chord note does not have LinkNext"

        testCase "Fixes incorrect crowd events" <| fun _ ->
            let events = ResizeArray(seq { Event("E0", 100); Event("E1", 200); Event("E2", 300) })
            let arr = InstrumentalArrangement(Events = events)

            EOFFixes.fixCrowdEvents arr

            Expect.hasLength arr.Events 3 "Number of events is unchanged"
            Expect.exists arr.Events (fun e -> e.Code = "e0") "E0 -> e0"
            Expect.exists arr.Events (fun e -> e.Code = "e1") "E1 -> e1"
            Expect.exists arr.Events (fun e -> e.Code = "e2") "E2 -> e2"

        testCase "Does not change correct crowd events" <| fun _ ->
            let events = ResizeArray(seq { Event("E3", 100); Event("E13", 200); Event("D3", 300); Event("E13", 400); })
            let arr = InstrumentalArrangement(Events = events)

            EOFFixes.fixCrowdEvents arr

            Expect.hasLength arr.Events 4 "Number of events is unchanged"
            Expect.equal arr.Events.[0].Code "E3" "Event #1 code unchanged"
            Expect.equal arr.Events.[1].Code "E13" "Event #2 code unchanged"
            Expect.equal arr.Events.[2].Code "D3" "Event #3 code unchanged"
            Expect.equal arr.Events.[3].Code "E13" "Event #4 code unchanged"

        testCase "Fixes incorrect hand shape lengths" <| fun _ ->
            let cn = ResizeArray(seq { Note(IsLinkNext = true, SlideTo = 5y, Sustain = 1000) })
            let chord = Chord(ChordNotes = cn, IsLinkNext = true)
            let chords = ResizeArray(seq { chord })
            let hs = HandShape(0s, 0, 1500)
            let handShapes = ResizeArray(seq { hs })
            let levels = ResizeArray(seq { Level(Chords = chords, HandShapes = handShapes) })
            let arr = InstrumentalArrangement(Levels = levels)

            EOFFixes.fixChordSlideHandshapes arr

            Expect.equal hs.EndTime 1000 "Hand shape end time is correct"

        testCase "Moves anchor to the beginning of phrase" <| fun _ ->
            let anchor = Anchor(5y, 700)
            let anchors = ResizeArray(seq { anchor })
            let levels = ResizeArray(seq { Level(Anchors = anchors) })
            let phraseIterations = ResizeArray(seq { PhraseIteration(650, 0); PhraseIteration(1000, 1) })
            let arr = InstrumentalArrangement(Levels = levels, PhraseIterations = phraseIterations)

            EOFFixes.fixPhraseStartAnchors arr

            Expect.equal anchor.Time 650 "Anchor time is correct"
    ]

[<Tests>]
let phraseMoverTests =
    testList "Arrangement Improver (Phrase Mover)" [
        testCase "Can move phrase to next note" <| fun _ ->
            let phrases = ResizeArray(seq { Phrase("mover1", 0uy, PhraseMask.None) })
            let iter = PhraseIteration(1000, 0)
            let iterations = ResizeArray(seq { iter })
            let notes = ResizeArray(seq { Note(Time = 1200) })
            let levels = ResizeArray(seq { Level(Notes = notes) })
            let arr = InstrumentalArrangement(Phrases = phrases, PhraseIterations = iterations, Levels = levels)

            PhraseMover.improve arr

            Expect.equal iter.Time 1200 "Phrase iteration was moved to correct time"

        testCase "Can move phrase to chord" <| fun _ ->
            let phrases = ResizeArray(seq { Phrase("mover2", 0uy, PhraseMask.None) })
            let iter = PhraseIteration(1000, 0)
            let iterations = ResizeArray(seq { iter })
            let notes = ResizeArray(seq { Note(Time = 1200) })
            let chords = ResizeArray(seq { Chord(Time = 1600) })
            let levels = ResizeArray(seq { Level(Notes = notes, Chords = chords) })
            let arr = InstrumentalArrangement(Phrases = phrases, PhraseIterations = iterations, Levels = levels)

            PhraseMover.improve arr

            Expect.equal iter.Time 1600 "Phrase iteration was moved to correct time"

        testCase "Can move phrase beyond multiple notes at the same time code" <| fun _ ->
            let phrases = ResizeArray(seq { Phrase("mover2", 0uy, PhraseMask.None) })
            let iter = PhraseIteration(1000, 0)
            let iterations = ResizeArray(seq { iter })
            let notes = ResizeArray(seq { Note(Time = 1200); Note(String = 1y, Time = 1200); Note(String = 2y, Time = 1200); Note(Time = 2500) })
            let levels = ResizeArray(seq { Level(Notes = notes) })
            let arr = InstrumentalArrangement(Phrases = phrases, PhraseIterations = iterations, Levels = levels)

            PhraseMover.improve arr

            Expect.equal iter.Time 2500 "Phrase iteration was moved to correct time"

        testCase "Can move a phrase on the same time code as a note" <| fun _ ->
            let phrases = ResizeArray(seq { Phrase("mover2", 0uy, PhraseMask.None) })
            let iter = PhraseIteration(1000, 0)
            let iterations = ResizeArray(seq { iter })
            let notes = ResizeArray(seq { Note(Time = 1000); Note(Time = 7500) })
            let levels = ResizeArray(seq { Level(Notes = notes) })
            let arr = InstrumentalArrangement(Phrases = phrases, PhraseIterations = iterations, Levels = levels)

            PhraseMover.improve arr

            Expect.equal iter.Time 7500 "Phrase iteration was moved to correct time"

        testCase "Section is also moved" <| fun _ ->
            let phrases = ResizeArray(seq { Phrase("mover1", 0uy, PhraseMask.None) })
            let iter = PhraseIteration(1000, 0)
            let iterations = ResizeArray(seq { iter })
            let section = Section("", 1000, 1s)
            let sections = ResizeArray(seq { section })
            let notes = ResizeArray(seq { Note(Time = 7500) })
            let levels = ResizeArray(seq { Level(Notes = notes) })
            let arr = InstrumentalArrangement(Phrases = phrases, PhraseIterations = iterations, Sections = sections, Levels = levels)

            PhraseMover.improve arr

            Expect.equal section.Time 7500 "Section was moved to correct time"

        testCase "Anchor is also moved" <| fun _ ->
            let phrases = ResizeArray(seq { Phrase("mover1", 0uy, PhraseMask.None) })
            let iter = PhraseIteration(1000, 0)
            let iterations = ResizeArray(seq { iter })
            let notes = ResizeArray(seq { Note(Time = 7500) })
            let anchors = ResizeArray(seq { Anchor(Time = 1000) })
            let levels = ResizeArray(seq { Level(Notes = notes, Anchors = anchors) })
            let arr = InstrumentalArrangement(Phrases = phrases, PhraseIterations = iterations, Levels = levels)

            PhraseMover.improve arr

            Expect.hasLength anchors 1 "One anchor exists"
            Expect.exists anchors (fun a -> a.Time = 7500) "Anchor was moved to correct time"

        testCase "Throws an exception when no integer given" <| fun _ ->
            let phrases = ResizeArray(seq { Phrase("mover", 0uy, PhraseMask.None) })
            let iterations = ResizeArray(seq { PhraseIteration(1000, 0) })
            let arr = InstrumentalArrangement(Phrases = phrases, PhraseIterations = iterations)

            Expect.throwsC (fun _ -> PhraseMover.improve arr)
                           (fun ex -> Expect.stringContains ex.Message "Unable to parse" "Correct exception was thrown")
    ]

[<Tests>]
let customEventTests =
    testList "Arrangement Improver (Custom Events)" [
        testCase "Anchor width 3 event" <| fun _ ->
            let anchor = Anchor(1y, 100)
            let anchors = ResizeArray(seq { anchor })
            let levels = ResizeArray(seq { Level(Anchors = anchors) })
            let events = ResizeArray(seq { Event("w3", 100) })
            let arr = InstrumentalArrangement(Events = events, Levels = levels)

            CustomEvents.improve arr

            Expect.equal anchor.Width 3y "Anchor has correct width"

        testCase "Anchor width 3 event can change fret" <| fun _ ->
            let anchor = Anchor(21y, 180)
            let anchors = ResizeArray(seq { anchor })
            let levels = ResizeArray(seq { Level(Anchors = anchors) })
            let events = ResizeArray(seq { Event("w3-22", 100) })
            let arr = InstrumentalArrangement(Events = events, Levels = levels)

            CustomEvents.improve arr

            Expect.equal anchor.Width 3y "Anchor has correct width"
            Expect.equal anchor.Fret 22y "Anchor has correct fret"

        testCase "Remove beats event" <| fun _ ->
            let beats = ResizeArray(seq { Ebeat(100, -1s); Ebeat(200, -1s); Ebeat(300, -1s); Ebeat(400, -1s); Ebeat(500, -1s); })
            let events = ResizeArray(seq { Event("removebeats", 400) })
            let arr = InstrumentalArrangement(Events = events, Ebeats = beats)

            CustomEvents.improve arr

            Expect.hasLength arr.Ebeats 3 "Two beats were removed"

        testCase "Slide-out event works for normal chord" <| fun _ ->
            let phrases = ResizeArray(seq { Phrase("", 0uy, PhraseMask.None) })
            let iterations = ResizeArray(seq { PhraseIteration(0, 0) })
            let templates = ResizeArray(seq { ChordTemplate("", "", [| 1y; 3y; -1y; -1y; -1y; -1y; |], [| 1y; 3y; -1y; -1y; -1y; -1y; |]) })
            let cn = ResizeArray(seq { Note(String = 0y, Fret = 1y, Sustain = 1000, SlideUnpitchTo = 7y)
                                       Note(String = 1y, Fret = 3y, Sustain = 1000, SlideUnpitchTo = 9y) })
            let chords = ResizeArray(seq { Chord(ChordNotes = cn) })
            let hs = HandShape(0s, 0, 1000)
            let handShapes = ResizeArray(seq { hs })
            let levels = ResizeArray(seq { Level(Chords = chords, HandShapes = handShapes) })
            let events = ResizeArray(seq { Event("so", 0) })
            let arr = InstrumentalArrangement(Phrases = phrases, PhraseIterations = iterations, ChordTemplates = templates, Events = events, Levels = levels)

            CustomEvents.improve arr

            Expect.hasLength arr.ChordTemplates 2 "A chord template was created"
            Expect.equal arr.ChordTemplates.[1].Frets.[0] 7y "Fret is correct"
            Expect.equal arr.ChordTemplates.[1].Frets.[1] 9y "Fret is correct"
            Expect.equal arr.ChordTemplates.[1].Fingers.[0] 1y "Fingering is correct"
            Expect.equal arr.ChordTemplates.[1].Fingers.[1] 3y "Fingering is correct"
            Expect.hasLength arr.Levels.[0].HandShapes 2 "A hand shape was created"
            Expect.equal arr.Levels.[0].HandShapes.[1].EndTime 1001 "Second hand shape ends at end of sustain + 1ms"
            Expect.isTrue (hs.EndTime < 1000) "First hand shape was shortened"

        testCase "Slide-out event works for link-next chord" <| fun _ ->
            let phrases = ResizeArray(seq { Phrase("", 0uy, PhraseMask.None) })
            let iterations = ResizeArray(seq { PhraseIteration(0, 0) })
            let templates = ResizeArray(seq { ChordTemplate("", "", [| -1y; -1y; 2y; 2y; -1y; -1y; |], [| -1y; -1y; 5y; 5y; -1y; -1y; |]) })
            let cn = ResizeArray(seq { Note(String = 2y, Fret = 5y, Sustain = 1000, IsLinkNext = true)
                                       Note(String = 3y, Fret = 5y, Sustain = 1000, IsLinkNext = true) })
            let chords = ResizeArray(seq { Chord(ChordNotes = cn, IsLinkNext = true) })
            let notes = ResizeArray(seq { Note(Time = 1000, String = 2y, Fret = 5y, Sustain = 500, SlideUnpitchTo = 12y)
                                          Note(Time = 1000, String = 3y, Fret = 5y, Sustain = 500, SlideUnpitchTo = 12y) })
            let hs = HandShape(0s, 0, 1500) // Includes sustain of slide-out notes
            let handShapes = ResizeArray(seq { hs })
            let levels = ResizeArray(seq { Level(Notes = notes, Chords = chords, HandShapes = handShapes) })
            let events = ResizeArray(seq { Event("so", 1000) })
            let arr = InstrumentalArrangement(Phrases = phrases, PhraseIterations = iterations, ChordTemplates = templates, Events = events, Levels = levels)

            CustomEvents.improve arr

            Expect.hasLength arr.ChordTemplates 2 "A chord template was created"
            Expect.equal arr.ChordTemplates.[1].Frets.[2] 12y "Fret is correct"
            Expect.equal arr.ChordTemplates.[1].Frets.[3] 12y "Fret is correct"
            Expect.equal arr.ChordTemplates.[1].Fingers.[2] 2y "Fingering is correct"
            Expect.equal arr.ChordTemplates.[1].Fingers.[3] 2y "Fingering is correct"
            Expect.hasLength arr.Levels.[0].HandShapes 2 "A hand shape was created"
            Expect.equal arr.Levels.[0].HandShapes.[1].EndTime 1501 "Second hand shape ends at end of sustain + 1ms"
            Expect.isTrue (hs.EndTime < 1500) "First hand shape was shortened"
    ]

[<Tests>]
let handShapeAdjusterTests =
    testList "Arrangement Improver (Hand Shape Adjuster)" [
        testCase "Shortens handshape length" <| fun _ ->
            let beats = ResizeArray(seq { Ebeat(500, -1s); Ebeat(1000, -1s); Ebeat(1500, -1s); Ebeat(2500, -1s) })
            let chords = ResizeArray(seq { Chord(Time = 1000); Chord(ChordId = 1s, Time = 2000) })
            let hs1 = HandShape(0s, 1000, 2000)
            let hs2 = HandShape(1s, 2000, 3000)
            let handShapes = ResizeArray(seq { hs1; hs2 })
            let levels = ResizeArray(seq { Level(Chords = chords, HandShapes = handShapes) })
            let arr = InstrumentalArrangement(Ebeats = beats, Levels = levels)

            HandShapeAdjuster.improve arr

            Expect.isTrue (hs1.EndTime < 2000) "Hand shape was shortened"
            Expect.isTrue (hs1.StartTime < hs1.EndTime) "Hand shape end comes after the start"

        testCase "Shortens length of a really short hand shape" <| fun _ ->
            let beats = ResizeArray(seq { Ebeat(500, -1s); Ebeat(1000, -1s); Ebeat(1500, -1s); Ebeat(2500, -1s) })
            let chords = ResizeArray(seq { Chord(Time = 1950); Chord(ChordId = 1s, Time = 2000) })
            let hs1 = HandShape(0s, 1950, 2000)
            let hs2 = HandShape(1s, 2000, 3000)
            let handShapes = ResizeArray(seq { hs1; hs2 })
            let levels = ResizeArray(seq { Level(Chords = chords, HandShapes = handShapes) })
            let arr = InstrumentalArrangement(Ebeats = beats, Levels = levels)

            HandShapeAdjuster.improve arr

            Expect.isTrue (hs1.EndTime < 2000) "Hand shape was shortened"
            Expect.isTrue (hs1.StartTime < hs1.EndTime) "Hand shape end comes after the start"

        testCase "Does not fail on handshapes that exceed the last beat" <| fun _ ->
            let beats = ResizeArray(seq { Ebeat(500, -1s); Ebeat(1000, -1s); Ebeat(1500, -1s); Ebeat(2500, -1s) })
            let hs1 = HandShape(0s, 2500, 2600)
            let hs2 = HandShape(0s, 2600, 2800)
            let handShapes = ResizeArray(seq { hs1; hs2 })
            let levels = ResizeArray(seq { Level(HandShapes = handShapes) })
            let arr = InstrumentalArrangement(Ebeats = beats, Levels = levels)

            HandShapeAdjuster.improve arr

            Expect.isTrue (hs1.EndTime < 2600) "Hand shape was shortened"
    ]

[<Tests>]
let basicFixTests =
    testList "Arrangement Improver (Basic Fixes)" [
        testCase "Filters characters in phrase names" <| fun _ ->
            let phrases = ResizeArray(seq { Phrase("\"TEST\"", 0uy, PhraseMask.None)
                                            Phrase("'TEST'_(2)", 0uy, PhraseMask.None) })
            let arr = InstrumentalArrangement(Phrases = phrases)

            BasicFixes.validatePhraseNames arr

            Expect.equal phrases.[0].Name "TEST" "First phrase name was changed"
            Expect.equal phrases.[1].Name "TEST_2" "Second phrase name was changed"
    ]

[<Tests>]
let applyAllTests =
    testList "Arrangement Improver (Apply All Fixes)" [
        testCase "Extra anchors are not created when moving phrases" <| fun _ ->
            let beats = ResizeArray(seq { Ebeat(900, 0s); Ebeat(1000, -1s); Ebeat(1200, -1s) })
            let phrases = ResizeArray(seq { Phrase("mover2", 0uy, PhraseMask.None); Phrase("END", 0uy, PhraseMask.None) })
            let iterations = ResizeArray(seq { PhraseIteration(1000, 0); PhraseIteration(1900, 1) })
            let notes = ResizeArray(seq { Note(Time = 1000); Note(Time = 1200) })
            let anchors = ResizeArray(seq { Anchor(1y, 1200) })
            let levels = ResizeArray(seq { Level(Notes = notes, Anchors = anchors) })
            let arr = InstrumentalArrangement(Phrases = phrases, PhraseIterations = iterations, Levels = levels, Ebeats = beats)
            arr.MetaData.SongLength <- 2000

            ArrangementImprover.applyAll arr

            Expect.hasLength anchors 1 "No new anchors were created"
            Expect.equal anchors.[0].Time 1200 "Anchor is at correct position"
    ]
