﻿namespace Rocksmith2014.DLCProject

open System
open System.IO
open System.Xml
open Rocksmith2014.XML
open Rocksmith2014.Common

type ArrangementName =
    | Lead = 0
    | Combo = 1
    | Rhythm = 2
    | Bass = 3

type RouteMask =
    | None = 0
    | Lead = 1
    | Rhythm = 2
    | Any = 3
    | Bass = 4

type ArrangementPriority =
    | Main = 0
    | Alternative = 1
    | Bonus = 2

type AudioFile = { Path : string; Volume : float }

type Instrumental =
    { XML : string
      Name : ArrangementName
      RouteMask : RouteMask
      Priority : ArrangementPriority
      ScrollSpeed : float
      BassPicked : bool
      Tuning : int16 array
      TuningPitch : double
      BaseTone : string
      Tones : string list
      CustomAudio : AudioFile option
      MasterID : int
      PersistentID : Guid }

type Vocals =
    { XML : string
      Japanese : bool
      CustomFont : string option
      MasterID : int
      PersistentID : Guid }

type Showlights =
    { XML : string }

type Arrangement =
    | Instrumental of Instrumental
    | Vocals of Vocals
    | Showlights of Showlights

module Arrangement =
    /// Returns the master ID of an arrangement.
    let getMasterId = function
        | Vocals v -> v.MasterID
        | Instrumental i -> i.MasterID
        | Showlights _ -> failwith "No"

    /// Returns the persistent ID of an arrangement.
    let getPersistentId = function
        | Vocals v -> v.PersistentID
        | Instrumental i -> i.PersistentID
        | Showlights _ -> failwith "No"

    /// Returns the name of an arrangement.
    let getName (arr: Arrangement) generic =
        match arr with
        | Vocals v when v.Japanese && not generic -> "JVocals"
        | Vocals _ -> "Vocals"
        | Showlights _ -> "Showlights"
        | Instrumental i -> i.Name.ToString()

    /// Returns a humanized name of an arrangement.
    let getHumanizedName arr =
        match arr with
        | Instrumental inst ->
            let prefix =
                match inst.Priority with
                | ArrangementPriority.Main -> String.Empty
                | ArrangementPriority.Alternative -> "Alt. "
                | ArrangementPriority.Bonus -> "Bonus "
                | _ -> failwith "Impossible."

            sprintf "%s%s" prefix (string inst.RouteMask)

        | Vocals v ->
            let prefix =
                if v.Japanese then "Japanese " else String.Empty

            sprintf "%sVocals" prefix

        | Showlights _ -> "Show Lights"

    /// Returns the XML file of an arrangement.
    let getFile = function
        | Vocals v -> v.XML
        | Instrumental i -> i.XML
        | Showlights s -> s.XML

    let pickInstrumental = function Instrumental i -> Some i | _ -> None
    let pickVocals = function Vocals v -> Some v | _ -> None
    let pickShowlights = function Showlights s -> Some s | _ -> None

    /// Returns the comparable values for sorting arrangements.
    let sorter = function
        | Instrumental i -> (LanguagePrimitives.EnumToValue i.RouteMask), (LanguagePrimitives.EnumToValue i.Priority)
        | Vocals v -> 5, if v.Japanese then 1 else 0
        | Showlights _ -> 6, 0

    /// Loads an arrangement from a file.
    let fromFile localize (fileName: string) =
        try
            let rootName =
                using (XmlReader.Create fileName)
                      (fun reader -> reader.MoveToContent() |> ignore; reader.LocalName)
    
            match rootName with
            | "song" ->
                let metadata = MetaData.Read fileName
                let toneInfo = InstrumentalArrangement.ReadToneNames fileName
                let baseTone =
                    if isNull toneInfo.BaseToneName then
                        metadata.Arrangement.ToLowerInvariant() + "_base"
                    else
                        toneInfo.BaseToneName
                let tones =
                    toneInfo.Names
                    |> Array.choose Option.ofString
                    |> Array.toList
    
                let routeMask =
                    if metadata.ArrangementProperties.PathBass then RouteMask.Bass
                    elif metadata.ArrangementProperties.PathRhythm then RouteMask.Rhythm
                    else RouteMask.Lead
    
                let name =
                    match ArrangementName.TryParse metadata.Arrangement with
                    | true, name -> name
                    | false, _ ->
                        match routeMask with
                        | RouteMask.Bass -> ArrangementName.Bass
                        | RouteMask.Rhythm -> ArrangementName.Rhythm
                        | _ -> ArrangementName.Lead
    
                let arr =
                    { XML = fileName
                      Name = name
                      Priority =
                        if metadata.ArrangementProperties.Represent then ArrangementPriority.Main
                        elif metadata.ArrangementProperties.BonusArrangement then ArrangementPriority.Bonus
                        else ArrangementPriority.Alternative
                      Tuning = metadata.Tuning.Strings
                      TuningPitch = Utils.centsToTuningPitch(float metadata.CentOffset)
                      RouteMask = routeMask
                      ScrollSpeed = 1.3
                      BaseTone = baseTone
                      Tones = tones
                      BassPicked = metadata.ArrangementProperties.BassPick
                      MasterID = RandomGenerator.next()
                      PersistentID = Guid.NewGuid()
                      CustomAudio = None }
                    |> Arrangement.Instrumental
                Ok (arr, Some metadata)
    
            | "vocals" ->
                // Attempt to infer whether the lyrics are Japanese from the filename
                let isJapanese =
                    fileName.Contains("jvocal", StringComparison.OrdinalIgnoreCase) ||
                    fileName.Contains("jlyric", StringComparison.OrdinalIgnoreCase)
    
                // Try to find custom font for Japanese vocals
                let customFont =
                    let fontFile = Path.Combine(IO.Path.GetDirectoryName fileName, "lyrics.dds")
                    if isJapanese && File.Exists fontFile then Some fontFile else None
    
                let arr =
                    { XML = fileName
                      Japanese = isJapanese
                      CustomFont = customFont
                      MasterID = RandomGenerator.next()
                      PersistentID = Guid.NewGuid() }
                    |> Arrangement.Vocals
                Ok (arr, None)
    
            | "showlights" ->
                let arr = Arrangement.Showlights { XML = fileName }
                Ok (arr, None)
    
            | _ -> Error (localize "unknownArrangementError")
        with ex -> Error ex.Message
    
    /// Reads the tone info from the arrangement's XML file.
    let updateToneInfo (inst: Instrumental) updateBaseTone =
        let toneInfo = InstrumentalArrangement.ReadToneNames inst.XML
        let tones =
            toneInfo.Names
            |> Array.choose Option.ofString
            |> Array.toList

        if updateBaseTone && not <| isNull toneInfo.BaseToneName then
            { inst with Tones = tones; BaseTone = toneInfo.BaseToneName }
        else
            { inst with Tones = tones }
