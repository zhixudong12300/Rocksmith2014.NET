﻿module DLCBuilder.Utils

open Pfim
open System
open System.IO
open System.Runtime.InteropServices
open Avalonia.Platform
open Avalonia.Media.Imaging
open Avalonia
open Rocksmith2014.PSARC
open Rocksmith2014.Common
open Rocksmith2014.Common.Manifest
open Rocksmith2014.DLCProject
open Rocksmith2014.XML.Processing
open Rocksmith2014.XML

/// Converts a Pfim DDS bitmap into an Avalonia bitmap.
let private avaloniaBitmapFromDDS (fileName: string) =
    use image = Pfim.FromFile fileName
    let pxFormat, data, stride =
        match image.Format with
        | ImageFormat.R5g6b5 -> PixelFormat.Rgb565, image.Data, image.Stride
        | ImageFormat.Rgb24 ->
            let pixels = image.DataLen / 3
            let newDataLen = pixels * 4
            let newData = Array.zeroCreate<byte> newDataLen
            for i = 0 to pixels - 1 do
                newData.[i * 4] <- image.Data.[i * 3]
                newData.[i * 4 + 1] <- image.Data.[i * 3 + 1]
                newData.[i * 4 + 2] <- image.Data.[i * 3 + 2]
                newData.[i * 4 + 3] <- 255uy

            let stride = image.Width * 4
            PixelFormat.Bgra8888, newData, stride
        | _ -> PixelFormat.Bgra8888, image.Data, image.Stride
    let pinnedArray = GCHandle.Alloc(data, GCHandleType.Pinned)
    let addr = pinnedArray.AddrOfPinnedObject()
    let bm = new Bitmap(pxFormat, AlphaFormat.Unpremul, addr, PixelSize(image.Width, image.Height), Vector(96., 96.), stride)
    pinnedArray.Free()
    bm

/// Loads a bitmap from the given path.
let loadBitmap (path: string) =
    match path with
    | EndsWith "dds" -> avaloniaBitmapFromDDS path
    | _ -> new Bitmap(path)

/// Disposes the old cover art and loads a new one from the given path.
let changeCoverArt (coverArt: Bitmap option) newPath =
    coverArt |> Option.iter (fun old -> old.Dispose())
    File.tryMap loadBitmap newPath

/// Imports tones from a PSARC file.
let importTonesFromPSARC (psarcPath: string) = async {
    use psarc = PSARC.ReadFile psarcPath
    let! jsons =
        psarc.Manifest
        |> List.filter (String.endsWith "json")
        |> List.map (fun x -> async {
            let data = MemoryStreamPool.Default.GetStream()
            do! psarc.InflateFile(x, data)
            return data })
        |> Async.Sequential

    let! manifests =
        jsons
        |> Array.map (fun data -> async {
            try
                let! a = using data Manifest.fromJsonStream
                return Some (Manifest.getSingletonAttributes a)
            with _ -> return None })
        |> Async.Parallel

    return
        manifests
        |> Array.choose (Option.bind (fun a -> Option.ofObj a.Tones))
        |> Array.concat
        |> Array.distinctBy (fun x -> x.Key) }

/// Creates the path for the preview audio from the main audio path.
let previewPathFromMainAudio (audioPath: string) =
    let dir = Path.GetDirectoryName audioPath
    let fn = Path.GetFileNameWithoutExtension audioPath
    let ext = Path.GetExtension audioPath
    Path.Combine(dir, $"{fn}_preview{ext}")

/// Removes an option from the list if it is Some.
let removeSelected list = function
    | None -> list
    | Some selected -> List.remove selected list

/// Checks the project's arrangements for issues.
let checkArrangements (project: DLCProject) =
    project.Arrangements
    |> List.map (function
        | Instrumental inst ->
            let issues =
                InstrumentalArrangement.Load inst.XML
                |> ArrangementChecker.runAllChecks
            inst.XML, issues
        | Vocals v when Option.isNone v.CustomFont ->
            let issues =
                Vocals.Load v.XML
                |> ArrangementChecker.checkVocals
                |> Option.toList
            v.XML, issues
        | Showlights sl ->
            let issues =
                 ShowLights.Load sl.XML
                 |> ArrangementChecker.checkShowlights
                 |> Option.toList
            sl.XML, issues
        | Vocals v ->
            v.XML, [])
    |> Map.ofList

/// Adds descriptors to tones that have none.
let addDescriptors tone =
    let descs =
        match tone.ToneDescriptors with
        | null | [||] ->
            ToneDescriptor.getDescriptionsOrDefault tone.Name
            |> Array.map (fun x -> x.UIName)
        | descriptors -> descriptors

    { tone with ToneDescriptors = descs; SortOrder = Nullable(); NameSeparator = " - " }

/// Adds the given tones into the project.
let addTones (state: State) tones =
    { state with Project = { state.Project with Tones = List.map addDescriptors tones @ state.Project.Tones }
                 Overlay = NoOverlay }
