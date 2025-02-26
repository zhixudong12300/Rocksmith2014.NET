open System
open System.Diagnostics
open System.IO
open System.Text.RegularExpressions
open Rocksmith2014.Common
open Rocksmith2014.Common.Manifest
open Rocksmith2014.Conversion
open Rocksmith2014.DD
open Rocksmith2014.PSARC
open Rocksmith2014.SNG

let benchmarkDDGeneration (psarcPath: string) = async {
    let config =
        { PhraseSearch = PhraseSearch.WithThreshold 80
          LevelCountGeneration = LevelCountGeneration.Simple }

    printfn "Processing: %s" (Path.GetFileName psarcPath)

    use psarc = PSARC.ReadFile psarcPath

    return!
        psarc.Manifest
        |> List.filter (fun x -> x.EndsWith ".sng" && not <| x.Contains "vocal")
        |> List.map (fun sngPath -> async {
            //printfn "Arrangement: %s" sngPath

            let sw = Stopwatch.StartNew()

            use! data = psarc.GetEntryStream sngPath
            let! sng = SNG.fromStream data PC
            let xml = ConvertInstrumental.sngToXml None sng

            do! xml.RemoveDD() |> Async.AwaitTask
            ignore <| Generator.generateForArrangement config xml

            sw.Stop()
            //printfn "Time: %i ms" sw.ElapsedMilliseconds
            return sngPath, sw.ElapsedMilliseconds })
        |> Async.Sequential }

let getOddVolumeValues (psarcPath: string) = async {
    use psarc = PSARC.ReadFile psarcPath

    let! oddVolumes =
        psarc.Manifest
        |> List.filter (fun x -> x.EndsWith ".json" && not <| x.Contains "vocal")
        |> List.map (fun jsonPath -> async {
            try
                use! data = psarc.GetEntryStream jsonPath
                let str = using (new StreamReader(data)) (fun reader -> reader.ReadToEnd())

                let matched = Regex.Match(str, "Volume\": \"-[0-9.]*[^0-9.][0-9.]*\"")
                if matched.Success then
                    return Some matched.Value
                else
                    return None
            with _ ->
                return None })
        |> Async.Sequential

    return oddVolumes |> Array.choose id }

let printOddVolumeResults directory =
    Directory.EnumerateFiles(directory, "*_p.psarc", SearchOption.AllDirectories)
    |> Seq.map getOddVolumeValues
    |> Async.Sequential
    |> Async.RunSynchronously
    |> Seq.collect id
    |> Seq.iter (printfn "%s")

let getSortValues (psarcPath: string) = async {
    use psarc = PSARC.ReadFile psarcPath

    use! manifestData =
        psarc.Manifest
        |> List.find (fun x -> x.EndsWith ".json" && not <| x.Contains "vocal")
        |> psarc.GetEntryStream
    let! manifest = Manifest.fromJsonStream manifestData
    let attributes = manifest |> Manifest.getSingletonAttributes
    return seq {
        let artistLower = attributes.ArtistName.ToLowerInvariant()
        if attributes.ArtistNameSort.ToLowerInvariant() <> artistLower then
            yield (attributes.ArtistName, attributes.ArtistNameSort)
        }
    }

let printSortValueResults directory =
    Directory.EnumerateFiles(directory, "*_p.psarc", SearchOption.AllDirectories)
    |> Seq.map getSortValues
    |> Async.Sequential
    |> Async.RunSynchronously
    |> Seq.collect id
    |> Seq.iter (printfn "%A")

let collectToneVolumes (psarcPath: string) = async {
    //printfn "Processing: %s" (Path.GetFileName psarcPath)

    use psarc = PSARC.ReadFile psarcPath

    let! volumeValues =
        psarc.Manifest
        |> List.filter (fun x -> x.EndsWith ".json" && not <| x.Contains "vocal")
        |> List.map (fun jsonPath -> async {
            try
                use! data = psarc.GetEntryStream jsonPath
                let! manifest = Manifest.fromJsonStream data
                let attributes = manifest |> Manifest.getSingletonAttributes

                return
                    attributes.Tones
                    |> Option.ofArray
                    |> Option.map (Array.map (Tone.fromDto >> (fun x -> x.Volume)))
            with _ ->
                return None })
        |> Async.Sequential

    let volumes =
        volumeValues
        |> Array.choose id
        |> Array.collect id

    volumes
    |> Array.tryFind (fun v -> v >= -2. || v <= -34.)
    |> Option.iter (printfn "%s: %f" psarcPath)

    return volumes }

let showToneVolumeResults directory =
    let volumes =
        Directory.EnumerateFiles(directory, "*_p.psarc", SearchOption.AllDirectories)
        |> Seq.map collectToneVolumes
        |> Async.Sequential
        |> Async.RunSynchronously
        |> Array.collect id

    printfn "MIN: %f" (Array.min volumes)
    printfn "MAX: %f" (Array.max volumes)
    printfn "AVG: %f" (Array.average volumes)

[<EntryPoint>]
let main argv =
    let directory = argv.[0]
    Directory.EnumerateFiles(directory, "*_p.psarc", SearchOption.AllDirectories)
    |> Seq.map benchmarkDDGeneration
    |> Async.Sequential
    |> Async.RunSynchronously
    |> Seq.collect id
    |> Seq.sortByDescending snd
    |> Seq.take 5
    |> Seq.iteri (fun i (fileName, time) -> printfn "\n%i: %s, %i ms" (i + 1) fileName time)

    0
