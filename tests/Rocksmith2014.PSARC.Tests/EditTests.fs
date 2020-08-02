﻿module EditTests

open Expecto
open System.IO
open Rocksmith2014.PSARC

let copyToMemory (fileName: string) =
    use file = File.OpenRead fileName
    let memory = new MemoryStream(int file.Length)
    file.CopyTo memory
    memory.Position <- 0L
    memory

[<Tests>]
let someTests =
  testList "Edit Files" [

    testCase "Manifest is same after null edit" <| fun _ ->
        use memory = copyToMemory "test_edit_p.psarc"
        use psarc = PSARC.Read memory
        let oldManifest = psarc.Manifest

        psarc.Edit(InMemory, (fun files -> ()))

        Expect.sequenceEqual psarc.Manifest oldManifest "Manifest is unchanged"

    testCase "Can be read after editing" <| fun _ ->
        use memory = copyToMemory "test_edit_p.psarc"
        let psarc = PSARC.Read memory
        let oldManifest = psarc.Manifest

        psarc.Edit(InMemory, (fun files -> ()))
        memory.Position <- 0L
        let psarc2 = PSARC.Read memory

        Expect.sequenceEqual psarc2.Manifest oldManifest "Manifest is unchanged"

    testCase "Can remove files" <| fun _ ->
        use memory = copyToMemory "test_edit_p.psarc"
        let psarc = PSARC.Read memory
        let oldManifest = psarc.Manifest
        let oldSize = memory.Length

        // Remove all files ending in "wem" from the archive
        psarc.Edit(InMemory, (fun files -> files.RemoveAll(fun x -> x.Name.EndsWith("wem")) |> ignore))
        memory.Position <- 0L
        let psarc2 = PSARC.Read memory

        Expect.equal psarc2.Manifest.Length (oldManifest.Length - 2) "Manifest size is correct"
        Expect.isTrue (memory.Length < oldSize) "Size is smaller"
  ]
