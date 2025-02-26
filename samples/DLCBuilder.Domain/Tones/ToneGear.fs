module DLCBuilder.ToneGear

open Microsoft.Extensions.FileProviders
open Rocksmith2014.Common
open Rocksmith2014.Common.Manifest
open System.Collections.Generic
open System.Reflection
open System.Text.Json

type GearSlot =
    | Amp
    | Cabinet
    | PrePedal of index: int
    | PostPedal of index: int
    | Rack of index: int

type GearKnob =
    { Name: string
      Key: string
      UnitType: string
      MinValue: float32
      MaxValue: float32
      ValueStep: float32
      DefaultValue: float32
      EnumValues: string array option }

type GearData =
    { Name: string
      Type: string
      Category: string
      Key: string
      Knobs: GearKnob array option }

type Repository =
    { Amps: GearData array
      AmpDict: IReadOnlyDictionary<string, GearData>
      Cabinets: GearData array
      CabinetDict: IReadOnlyDictionary<string, GearData>
      Pedals: GearData array
      PedalDict: IReadOnlyDictionary<string, GearData>
      Racks: GearData array
      RackDict: IReadOnlyDictionary<string, GearData>
      CabinetChoices: GearData array
      MicPositionsForCabinet: IReadOnlyDictionary<string, GearData array> }

let getPedalForSlot (gearList: Gear) gearSlot =
    match gearSlot with
    | Amp ->
        Some gearList.Amp
    | Cabinet ->
        Some gearList.Cabinet
    | PrePedal index ->
        gearList.PrePedals.[index]
    | PostPedal index ->
        gearList.PostPedals.[index]
    | Rack index ->
        gearList.Racks.[index]

/// Returns the knob values for the pedal in the given gear slot.
let getKnobValuesForGear (gearList: Gear) gearSlot =
    getPedalForSlot gearList gearSlot
    |> Option.map (fun x -> x.KnobValues)

let private getDefaultKnobValues gear =
    gear.Knobs
    |> Option.map (Array.map (fun knob -> knob.Key, knob.DefaultValue) >> Map.ofArray)
    |> Option.defaultValue Map.empty

/// Creates a pedal with default knob values from the gear data.
let createPedalForGear (gear: GearData) =
    { Key = gear.Key
      Type = gear.Type
      Category = None
      Skin = None
      SkinIndex = None
      KnobValues = getDefaultKnobValues gear }

let private loadGearData () = async {
    let provider = EmbeddedFileProvider(Assembly.GetExecutingAssembly())
    let options = FSharpJsonOptions.Create(ignoreNull=true)
    use gearDataFile = provider.GetFileInfo("Tones/tone_gear_data.json").CreateReadStream()
    return! JsonSerializer.DeserializeAsync<GearData[]>(gearDataFile, options) }

let loadRepository () = async {
    let! allGear = loadGearData ()

    let filterSort type' sortBy =
        allGear
        |> Array.filter (fun x -> x.Type = type')
        |> Array.sortBy sortBy

    let toDict = Array.map (fun x -> x.Key, x) >> readOnlyDict

    let data =
        [| "Amps", (fun x -> x.Name)
           "Cabinets", (fun x -> x.Name)
           "Pedals", (fun x -> x.Category + x.Name)
           "Racks", (fun x -> x.Category + x.Name) |]
        |> Array.Parallel.map (fun (gearType, sorter) ->
            let result = filterSort gearType sorter
            let dict = toDict result
            gearType, {| Array = result; Dictionary = dict |})
        |> readOnlyDict

    let cabinets = data.["Cabinets"].Array
    let cabinetChoices = cabinets |> Array.distinctBy (fun x -> x.Name)

    let micPositionsForCabinet =
        cabinets
        |> Array.groupBy (fun x -> x.Name)
        |> readOnlyDict

    return
        { Amps = data.["Amps"].Array
          AmpDict = data.["Amps"].Dictionary
          Cabinets = cabinets
          CabinetDict = data.["Cabinets"].Dictionary
          Pedals = data.["Pedals"].Array
          PedalDict = data.["Pedals"].Dictionary
          Racks = data.["Racks"].Array
          RackDict = data.["Racks"].Dictionary
          CabinetChoices = cabinetChoices
          MicPositionsForCabinet = micPositionsForCabinet } }

/// Returns the gear data for the pedal in the given gear slot.
let getGearDataForCurrentPedal repository (gearList: Gear) = function
    | Amp ->
        Some repository.AmpDict.[gearList.Amp.Key]
    | Cabinet ->
        Some repository.CabinetDict.[gearList.Cabinet.Key]
    | PrePedal index ->
        gearList.PrePedals.[index] |> Option.map (fun x -> repository.PedalDict.[x.Key])
    | PostPedal index ->
        gearList.PostPedals.[index] |> Option.map (fun x -> repository.PedalDict.[x.Key])
    | Rack index ->
        gearList.Racks.[index] |> Option.map (fun x -> repository.RackDict.[x.Key])

let emptyTone repository =
    let gear =
        let noPedals = Array.replicate 4 None

        { Amp = repository.Amps.[0] |> createPedalForGear
          Cabinet = repository.Cabinets.[0] |> createPedalForGear
          Racks = noPedals
          PrePedals = noPedals
          PostPedals = noPedals }

    { GearList = gear
      ToneDescriptors = [| "$[35720]CLEAN" |]
      NameSeparator = " - "
      Volume = -18.
      MacVolume = None
      Key = "new_tone"
      Name = "new_tone"
      SortOrder = None }
