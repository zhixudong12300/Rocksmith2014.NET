[<AutoOpen>]
module DLCBuilder.GeneralTypes

open System

type Locale =
    { Name: string
      ShortName: string }

    override this.ToString() = this.Name
    static member Default = { Name = "English"; ShortName = "en" }

type AsyncReply(f: bool -> unit) =
    member _.Reply(answer) = f answer

type IBitmapLoader =
    abstract member InvalidateCache : unit -> unit
    abstract member TryLoad : string -> bool

type IStringLocalizer =
    abstract member Translate : string -> string
    abstract member TranslateFormat : string * obj array -> string
    abstract member ChangeLocale : Locale -> unit
    abstract member LocaleFromShortName : string -> Locale

type AudioConversionType = NoConversion | ToWav | ToOgg

type MoveDirection = Up | Down

type BuildType = Test | Release | PitchShifted

type ArrangementAddingError =
    | MaxInstrumentals
    | MaxShowlights
    | MaxVocals

type BuildValidationError =
    | InvalidDLCKey
    | TitleEmpty
    | ArtistNameEmpty
    | AlbumArtNotFound
    | PreviewNotFound
    | MultipleTonesSameKey
    | ConflictingVocals
    | MissingBaseToneKey
    | SamePersistentID

type DownloadId = { Id: Guid; LocString: string }
