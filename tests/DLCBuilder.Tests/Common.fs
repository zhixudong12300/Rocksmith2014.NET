[<AutoOpen>]
module Common

open DLCBuilder
open Rocksmith2014.Common
open Rocksmith2014.DLCProject
open System

let albumArtLoaderStub =
    { new IBitmapLoader with
        member _.InvalidateCache() = ()
        member _.TryLoad _ = true }

let initialState =
    { Project = DLCProject.Empty
      SavedProject = DLCProject.Empty
      RecentFiles = List.empty
      Config = { Configuration.Default with ShowAdvanced = true }
      SelectedArrangementIndex = -1
      SelectedToneIndex = -1
      SelectedGear = None
      SelectedGearSlot = ToneGear.Amp
      SelectedImportTones = List.empty
      ManuallyEditingKnobKey = None
      ShowSortFields = false
      ShowJapaneseFields = false
      Overlay = NoOverlay
      RunningTasks = Set.empty
      StatusMessages = List.empty
      CurrentPlatform = if OperatingSystem.IsMacOS() then Mac else PC
      OpenProjectFile = None
      AvailableUpdate = None
      ArrangementIssues = Map.empty
      ToneGearRepository = None
      AlbumArtLoadTime = None
      AlbumArtLoader = albumArtLoaderStub }
