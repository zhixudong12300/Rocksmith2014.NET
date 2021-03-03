﻿module DLCBuilder.EditFunctions

open Rocksmith2014.Common
open Rocksmith2014.Common.Manifest
open Rocksmith2014.DLCProject
open Elmish
open System
open ToneGear

let private updateArrangement old updated state =
    let arrangements =
        state.Project.Arrangements
        |> List.update old updated
    { state with Project = { state.Project with Arrangements = arrangements }
                 SelectedArrangement = Some updated }

let private updateTone index updated state =
    let tones =
        state.Project.Tones
        |> List.updateAt index updated
    { state with Project = { state.Project with Tones = tones } }

let private fixPriority state routeMask arr =
    if arr.Priority = ArrangementPriority.Main
       && state.Project.Arrangements |> List.exists (function
            | Instrumental inst when inst <> arr ->
                inst.RouteMask = routeMask && inst.Priority = ArrangementPriority.Main
            | _ -> false) then
        ArrangementPriority.Alternative
    else
        arr.Priority

let editInstrumental state edit old inst =
    let updated, cmd =
        match edit with
        | SetArrangementName name ->
            let routeMask =
                match name with
                | ArrangementName.Lead -> RouteMask.Lead
                | ArrangementName.Rhythm -> RouteMask.Rhythm
                | ArrangementName.Combo ->
                    // The name of a bass arrangement cannot currently be changed
                    if inst.RouteMask = RouteMask.Bass then RouteMask.Rhythm else inst.RouteMask
                | ArrangementName.Bass -> RouteMask.Bass
                | _ -> failwith "Impossible failure."
            let priority = fixPriority state routeMask inst
            { inst with Name = name; RouteMask = routeMask; Priority = priority }, Cmd.none

        | SetRouteMask mask ->
            let priority = fixPriority state mask inst
            { inst with RouteMask = mask; Priority = priority }, Cmd.none

        | SetPriority priority ->
            { inst with Priority = priority }, Cmd.none

        | SetBassPicked picked ->
            { inst with BassPicked = picked }, Cmd.none

        | SetTuning (index, newTuning) ->
            { inst with Tuning = inst.Tuning |> Array.updateAt index newTuning }, Cmd.none

        | SetTuningPitch pitch ->
            { inst with TuningPitch = pitch }, Cmd.none

        | SetBaseTone tone ->
            { inst with BaseTone = tone }, Cmd.none

        | UpdateToneInfo ->
            Arrangement.updateToneInfo inst true, Cmd.none

        | SetScrollSpeed speed ->
            { inst with ScrollSpeed = speed }, Cmd.none

        | SetMasterId id ->
            { inst with MasterID = id }, Cmd.none

        | SetPersistentId id ->
            { inst with PersistentID = id }, Cmd.none

        | GenerateNewIds ->
            { inst with MasterID = RandomGenerator.next()
                        PersistentID = Guid.NewGuid() }, Cmd.none

        | SetCustomAudioPath (Some path) ->
            let cmd =
                if state.Config.AutoVolume && not <| String.endsWith ".wem" path then
                    Cmd.ofMsg <| CalculateVolume(CustomAudio(path))
                else
                    Cmd.none
        
            let customAudio =
                match inst.CustomAudio with
                | Some audio -> { audio with Path = path }
                | None -> { Path = path; Volume = state.Project.AudioFile.Volume }
            { inst with CustomAudio = Some customAudio }, cmd

        | SetCustomAudioPath None ->
            { inst with CustomAudio = None }, Cmd.none

        | SetCustomAudioVolume volume ->
            { inst with CustomAudio = Option.map (fun x -> { x with Volume = volume }) inst.CustomAudio }, Cmd.none

    updateArrangement old (Instrumental updated) state, cmd

let editConfig edit config =
    match edit with
    | SetCharterName name ->
        { config with CharterName = name }

    | SetAutoVolume autoVolume ->
        { config with AutoVolume = autoVolume }

    | SetShowAdvanced showAdvanced ->
        { config with ShowAdvanced = showAdvanced }

    | SetRemoveDDOnImport removeDD ->
        { config with RemoveDDOnImport = removeDD }

    | SetGenerateDD generateDD ->
        { config with GenerateDD = generateDD }

    | SetDDPhraseSearchEnabled phraseSearch ->
        { config with DDPhraseSearchEnabled = phraseSearch }

    | SetDDPhraseSearchThreshold threshold ->
        { config with DDPhraseSearchThreshold = threshold }

    | SetApplyImprovements improve ->
        { config with ApplyImprovements = improve }

    | SetSaveDebugFiles debug ->
        { config with SaveDebugFiles = debug }

    | SetCustomAppId appId ->
        { config with CustomAppId = appId }

    | SetConvertAudio convert ->
        { config with ConvertAudio = convert }

    | AddReleasePlatform platform ->
        { config with ReleasePlatforms = Set.add platform config.ReleasePlatforms }

    | RemoveReleasePlatform platform ->
        { config with ReleasePlatforms = Set.remove platform config.ReleasePlatforms }

    | SetTestFolderPath path ->
        { config with TestFolderPath = path }

    | SetProjectsFolderPath path ->
        { config with ProjectsFolderPath = path }

    | SetWwiseConsolePath path ->
        { config with WwiseConsolePath = Option.ofString path }

    | SetProfilePath path ->
        match path with
        | EndsWith "_PRFLDB" -> { config with ProfilePath = path }
        | _ -> config

let editProject edit project =
    match edit with
    | SetDLCKey key ->
        { project with DLCKey = key }

    | SetVersion version ->
        { project with Version = version }

    | SetArtistName artist ->
        { project with ArtistName = { project.ArtistName with Value = artist } }

    | SetArtistNameSort artistSort ->
        { project with ArtistName = { project.ArtistName with SortValue = artistSort } }

    | SetJapaneseArtistName artist ->
        { project with JapaneseArtistName = artist }

    | SetTitle title ->
        { project with Title = { project.Title with Value = title } }

    | SetTitleSort titleSort ->
        { project with Title = { project.Title with SortValue = titleSort } }

    | SetJapaneseTitle title ->
        { project with JapaneseTitle = title }

    | SetAlbumName album ->
        { project with AlbumName = { project.AlbumName with Value = album } }

    | SetAlbumNameSort albumSort ->
        { project with AlbumName = { project.AlbumName with SortValue = albumSort } }

    | SetYear year ->
        { project with Year = year }

    | SetAudioVolume volume ->
        { project with AudioFile = { project.AudioFile with Volume = volume } }

    | SetPreviewVolume volume ->
        { project with AudioPreviewFile = { project.AudioPreviewFile with Volume = volume } }

    | SetPreviewStartTime startTime ->
        { project with AudioPreviewStartTime = Some startTime }

let editTone state edit index =
    let tone = state.Project.Tones.[index]
    let updatedTone =
        match edit with
        | SetName name ->
            { tone with Name = name }

        | SetKey key ->
            { tone with Key = key }

        | SetVolume volume ->
            { tone with Volume = volume }

        | AddDescriptor ->
            { tone with ToneDescriptors = tone.ToneDescriptors |> Array.append [| ToneDescriptor.all.[0].UIName |] }

        | RemoveDescriptor ->
            { tone with ToneDescriptors = tone.ToneDescriptors.[1..] }

        | ChangeDescriptor (index, descriptor) ->
           { tone with ToneDescriptors = tone.ToneDescriptors |> Array.updateAt index descriptor.UIName }

        | RemovePedal ->
            let remove index = Utils.removeAndShift index
            let gearList =
                match state.SelectedGearType with
                | PrePedal index ->
                    { tone.GearList with PrePedals = tone.GearList.PrePedals |> remove index }
                | PostPedal index ->
                    { tone.GearList with PostPedals = tone.GearList.PostPedals |> remove index }
                | Rack index ->
                    { tone.GearList with Racks = tone.GearList.Racks |> remove index }
                | Amp | Cabinet ->
                    failwith "Cannot remove amp or cabinet"

            { tone with GearList = gearList }

        | SetPedal gear ->
            let currentPedal =
                match state.SelectedGearType with
                | Amp -> Some tone.GearList.Amp
                | Cabinet -> Some tone.GearList.Cabinet
                | PrePedal index -> tone.GearList.PrePedals.[index]
                | PostPedal index -> tone.GearList.PostPedals.[index]
                | Rack index -> tone.GearList.Racks.[index]

            match currentPedal with
            | Some currPedal when currPedal.Key = gear.Key ->
                tone
            | _ ->
                let newPedal = createPedalForGear gear
                let setPedal index = Array.updateAt index (Some newPedal)
                let gearList =
                    match state.SelectedGearType with
                    | Amp ->
                        { tone.GearList with Amp = newPedal }
                    | Cabinet ->
                        { tone.GearList with Cabinet = newPedal }
                    | PrePedal index ->
                        { tone.GearList with PrePedals = tone.GearList.PrePedals |> setPedal index }
                    | PostPedal index ->
                        { tone.GearList with PostPedals = tone.GearList.PostPedals |> setPedal index }
                    | Rack index ->
                        { tone.GearList with Racks = tone.GearList.Racks |> setPedal index }

                { tone with GearList = gearList }

        | SetKnobValue (knobKey, value) ->              
            match state.SelectedGear with
            | Some _ when state.SelectedGearType <> Cabinet ->
                getKnobValuesForGear tone.GearList state.SelectedGearType
                // Update the value only if the key exists
                |> Option.map (Map.change knobKey (Option.map (fun _ -> value)))
                |> function
                | None ->
                    tone
                | Some updatedKnobs ->
                    let updateKnobs index =
                        Array.mapi (fun i pedal ->
                            if i = index then
                                pedal |> Option.map (fun p -> { p with KnobValues = updatedKnobs })
                            else 
                                pedal)

                    let gearList =
                        match state.SelectedGearType with
                        | Amp ->
                            { tone.GearList with Amp = { tone.GearList.Amp with KnobValues = updatedKnobs } }
                        | Cabinet ->
                            tone.GearList
                        | PrePedal index ->
                            { tone.GearList with PrePedals = tone.GearList.PrePedals |> updateKnobs index }
                        | PostPedal index ->
                            { tone.GearList with PostPedals = tone.GearList.PostPedals |> updateKnobs index }
                        | Rack index ->
                            { tone.GearList with Racks = tone.GearList.Racks |> updateKnobs index }

                    { tone with GearList = gearList }
            | _ -> tone

    if updatedTone = tone then
        state, Cmd.none
    else
        updateTone index updatedTone state, Cmd.none

let editVocals state edit old vocals =
    let updated =
        match edit with
        | SetIsJapanese japanese -> { vocals with Japanese = japanese }
        | SetCustomFont font -> { vocals with CustomFont = font }
    updateArrangement old (Vocals updated) state, Cmd.none
