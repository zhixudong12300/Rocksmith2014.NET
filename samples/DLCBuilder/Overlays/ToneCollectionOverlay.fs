module DLCBuilder.Views.ToneCollectionOverlay

open Avalonia.Controls
open Avalonia.Controls.Shapes
open Avalonia.FuncUI
open Avalonia.FuncUI.Components
open Avalonia.FuncUI.DSL
open Avalonia.FuncUI.Types
open Avalonia.Input
open Avalonia.Layout
open Avalonia.Media
open DLCBuilder
open DLCBuilder.Media
open DLCBuilder.ToneGear
open Rocksmith2014.Common.Manifest
open System
open System.Text.RegularExpressions
open ToneCollection

let private translateDescription (description: string) =
    description.Split('|')
    |> Array.map translate
    |> String.concat " "

let private toneTemplate dispatch isOfficial =
    DataTemplateView<DbTone>.create (fun dbTone ->
        let brush =
            if dbTone.BassTone then
                Brushes.bass
            elif Regex.IsMatch(dbTone.Name, "lead|solo", RegexOptions.IgnoreCase) then
                Brushes.lead
            else
                Brushes.rhythm

        StackPanel.create [
            StackPanel.contextMenu (
                ContextMenu.create [
                    ContextMenu.viewItems [
                        if isOfficial then
                            MenuItem.create [
                                MenuItem.header (translate "AddToProjectMenuItem")
                                MenuItem.onClick (fun _ -> AddSelectedToneFromCollection |> dispatch)
                                MenuItem.inputGesture (KeyGesture(Key.Enter))
                            ]

                            MenuItem.create [ MenuItem.header "-" ]

                            MenuItem.create [
                                MenuItem.header (translate "AddToUserCollectionMenuItem")
                                MenuItem.onClick (fun _ -> AddOfficialToneToUserCollection |> dispatch)
                            ]
                        else
                            MenuItem.create [
                                MenuItem.header (translate "AddToProjectMenuItem")
                                MenuItem.onClick (fun _ -> AddSelectedToneFromCollection |> dispatch)
                                MenuItem.inputGesture (KeyGesture(Key.Enter))
                            ]

                            MenuItem.create [
                                MenuItem.header (translate "EditMenuItem")
                                MenuItem.onClick (fun _ ->
                                    FocusHelper.storeFocusedElement ()
                                    ShowUserToneEditor |> dispatch)
                                MenuItem.inputGesture (KeyGesture(Key.E))
                            ]

                            MenuItem.create [ MenuItem.header "-" ]

                            MenuItem.create [
                                MenuItem.header (translate "RemoveMenuItem")
                                MenuItem.onClick (fun _ -> DeleteSelectedUserTone |> dispatch)
                                MenuItem.inputGesture (KeyGesture(Key.Delete))
                            ]
                    ]
                ])
            StackPanel.background Brushes.Transparent
            StackPanel.width 470.
            StackPanel.orientation Orientation.Horizontal
            StackPanel.onDoubleTapped (fun _ -> AddSelectedToneFromCollection |> dispatch)
            StackPanel.children [
                PathIcon.create [
                    PathIcon.width 25.
                    PathIcon.height 25.
                    PathIcon.foreground brush
                    PathIcon.data Icons.guitar
                ]

                StackPanel.create [
                    StackPanel.margin 4.
                    StackPanel.children [
                        TextBlock.create [
                            TextBlock.text (
                                [ dbTone.Artist; dbTone.Title ]
                                |> List.filter String.notEmpty
                                |> String.concat " - ")
                        ]
                        TextBlock.create [ TextBlock.text dbTone.Name ]
                        TextBlock.create [ TextBlock.text (translateDescription dbTone.Description) ]
                    ]
                ]
            ]
        ])

let tonesList dispatch collectionState isOfficial =
    ListBox.create [
        ListBox.height 410.
        ListBox.width 500.
        ListBox.dataItems collectionState.Tones
        ListBox.itemTemplate (toneTemplate dispatch isOfficial)
        ListBox.onSelectedItemChanged (function
            | :? DbTone as tone ->
                tone |> Some |> SelectedToneChanged |> dispatch
            | _ ->
                None |> SelectedToneChanged |> dispatch)
        ListBox.onKeyDown (fun arg ->
            arg.Handled <- true
            match arg.Key with
            | Key.Left ->
                ChangePage Left |> dispatch
            | Key.Right ->
                ChangePage Right |> dispatch
            | Key.Enter ->
                AddSelectedToneFromCollection |> dispatch
            | Key.Delete when not isOfficial ->
                DeleteSelectedUserTone |> dispatch
            | Key.E when not isOfficial ->
                FocusHelper.storeFocusedElement ()
                ShowUserToneEditor |> dispatch
            | _ ->
                arg.Handled <- false
        )
    ]

let private paginationControls dispatch (collectionState: ToneCollectionState) =
    let currentPage = collectionState.QueryOptions.PageNumber

    Grid.create [
        DockPanel.dock Dock.Bottom
        Grid.horizontalAlignment HorizontalAlignment.Center
        Grid.margin 4.
        Grid.columnDefinitions "*,auto,*"
        Grid.children [
            // Previous Page
            RepeatButton.create [
                let isEnabled = currentPage > 1
                RepeatButton.classes [ "borderless-btn" ]
                RepeatButton.padding (10., 8.)
                RepeatButton.content (
                    PathIcon.create [
                        PathIcon.data Icons.chevronLeft
                        PathIcon.width 16.
                        PathIcon.height 16.
                    ])
                RepeatButton.onClick (fun _ -> ChangePage Left |> dispatch)
                RepeatButton.isEnabled isEnabled
            ]

            // Current Page / Total Pages
            TextBlock.create [
                Grid.column 1
                TextBlock.margin 8.
                TextBlock.minWidth 80.
                TextBlock.textAlignment TextAlignment.Center
                TextBlock.text (
                    if collectionState.TotalPages = 0 then
                        String.Empty
                    else
                        $"{currentPage} / {collectionState.TotalPages}")
            ]

            // Next Page
            RepeatButton.create [
                let isEnabled = currentPage < collectionState.TotalPages
                Grid.column 2
                RepeatButton.classes [ "borderless-btn" ]
                RepeatButton.padding (10., 8.)
                RepeatButton.content (
                    PathIcon.create [
                        PathIcon.data Icons.chevronRight
                        PathIcon.width 16.
                        PathIcon.height 16.
                    ])
                RepeatButton.onClick (fun _ -> ChangePage Right |> dispatch)
                RepeatButton.isEnabled isEnabled
            ]
        ]
    ]

let private collectionView dispatch (collectionState: ToneCollectionState) =
    DockPanel.create [
        DockPanel.children [
            // Search text box
            AutoFocusSearchBox.create [
                DockPanel.dock Dock.Top
                AutoFocusSearchBox.onTextChanged (Option.ofString >> SearchCollection >> dispatch)
            ]

            // Pagination
            paginationControls dispatch collectionState

            match collectionState.ActiveCollection with
            // Database file not found message
            | ActiveCollection.Official None ->
                StackPanel.create [
                    StackPanel.horizontalAlignment HorizontalAlignment.Center
                    StackPanel.verticalAlignment VerticalAlignment.Center
                    StackPanel.children [
                        TextBlock.create [
                            TextBlock.text (translate "OfficialTonesDbNotFound")
                        ]
                        Button.create [
                            Button.margin 4.
                            Button.padding (20., 10.)
                            Button.content (translate "ClickToDownloadTonesDb")
                            Button.onClick (fun _ -> DownloadOfficialTonesDatabase |> dispatch)
                        ]
                    ]
                ]
            // Tones list
            | ActiveCollection.Official _ ->
                tonesList dispatch collectionState true
            | ActiveCollection.User _ ->
                tonesList dispatch collectionState false
        ]
    ]

let private userToneEditor dispatch data =
    Grid.create [
        Grid.width 500.
        Grid.verticalAlignment VerticalAlignment.Center
        Grid.rowDefinitions "auto,auto,auto,auto,auto,auto,auto,auto"
        Grid.children [
            Button.create [
                Grid.row 0
                Button.content (translate "RemoveArtistInfo")
                Button.horizontalAlignment HorizontalAlignment.Center
                Button.padding (20., 5.)
                Button.onClick (fun _ -> UserToneEdit.RemoveArtistInfo |> EditUserToneData |> dispatch)
            ]

            TitledTextBox.create "ArtistName" [ Grid.row 1 ]
                [ FixedTextBox.text data.Artist
                  FixedTextBox.onTextChanged (UserToneEdit.SetArtist >> EditUserToneData >> dispatch) ]

            TitledTextBox.create "ArtistNameSort" [ Grid.row 2 ]
                [ FixedTextBox.text data.ArtistSort
                  FixedTextBox.onTextChanged (UserToneEdit.SetArtistSort >> EditUserToneData >> dispatch) ]

            TitledTextBox.create "Title" [ Grid.row 3 ]
                [ FixedTextBox.text data.Title
                  FixedTextBox.onTextChanged (UserToneEdit.SetTitle >> EditUserToneData >> dispatch) ]

            TitledTextBox.create "TitleSort" [ Grid.row 4 ]
                [ FixedTextBox.text data.TitleSort
                  FixedTextBox.onTextChanged (UserToneEdit.SetTitleSort >> EditUserToneData >> dispatch) ]

            TitledTextBox.create "Name" [ Grid.row 5 ]
                [ FixedTextBox.text data.Name
                  TextBox.onTextInput (fun e -> e.Text <- Rocksmith2014.DLCProject.StringValidator.toneName e.Text)
                  FixedTextBox.onTextChanged (UserToneEdit.SetName >> EditUserToneData >> dispatch) ]

            CheckBox.create [
                Grid.row 6
                CheckBox.content (translate "BassTone")
                CheckBox.isChecked data.BassTone
                CheckBox.onChecked (fun _ -> true |> UserToneEdit.SetIsBass |> EditUserToneData |> dispatch)
                CheckBox.onUnchecked (fun _ -> false |> UserToneEdit.SetIsBass |> EditUserToneData |> dispatch)
            ]

            StackPanel.create [
                Grid.row 7
                StackPanel.orientation Orientation.Horizontal
                StackPanel.horizontalAlignment HorizontalAlignment.Center
                StackPanel.children [
                    // Save Button
                    Button.create [
                        Button.margin 4.
                        Button.fontSize 18.
                        Button.padding (30., 10.)
                        Button.content (translate "Save")
                        Button.isEnabled (String.notEmpty data.Name)
                        Button.onClick (fun _ ->
                            FocusHelper.restoreFocus ()
                            ApplyUserToneEdit |> dispatch)
                    ]
                    // Cancel Button
                    Button.create [
                        Button.margin 4.
                        Button.fontSize 18.
                        Button.padding (30., 10.)
                        Button.content (translate "Cancel")
                        Button.onClick (fun _ ->
                            FocusHelper.restoreFocus ()
                            HideUserToneEditor |> dispatch)
                    ]
                ]
            ]
        ]
    ]

let private knobProgressBar gearData (pedal: Pedal option) knobName : IView list option =
    gearData.Knobs
    |> Option.bind (Array.tryFind (fun x -> x.Name = knobName))
    |> Option.map (fun knob ->
        [
            TextBlock.create [ TextBlock.text knobName ]
            ProgressBar.create [
                ProgressBar.minimum (float knob.MinValue)
                ProgressBar.maximum (float knob.MaxValue)
                ProgressBar.value (
                    pedal
                    |> Option.map (fun x -> x.KnobValues |> Map.find knob.Key |> float)
                    |> Option.defaultValue 1.
                )
            ]
        ])

let private pedals repository title gearList gearSlot =
    [
        TextBlock.create [
            TextBlock.text (translate title)
            TextBlock.horizontalAlignment HorizontalAlignment.Center
        ] |> generalize

        for i = 0 to 3 do
            match getGearDataForCurrentPedal repository gearList (gearSlot i) with
            | None ->
                ()
            | Some gearData ->
                let pedal = getPedalForSlot gearList (gearSlot i)

                Border.create [
                    Border.margin (0., 2.)
                    Border.padding 6.
                    Border.background "#222"
                    Border.cornerRadius 4.
                    Border.child (
                        StackPanel.create [
                            StackPanel.children [
                                TextBlock.create [
                                    TextBlock.text gearData.Name
                                ]

                                StackPanel.create [
                                    StackPanel.margin (10., 0.)
                                    StackPanel.children (
                                        [ "Mix"; "Gain"; "Rate" ]
                                        |> List.tryPick (knobProgressBar gearData pedal)
                                        |> Option.defaultValue List.empty)
                                ]
                            ]
                        ]
                    )
                ]
    ]

let private separator =
    Rectangle.create [
        Rectangle.height 2.
        Rectangle.fill Brushes.Gray
        Rectangle.margin (0., 10.)
    ] |> generalize

let private toneInfoPanel state collectionState =
    StackPanel.create [
        StackPanel.margin (0., 40., 0., 0.)
        StackPanel.width 230.
        StackPanel.children [
            match state.ToneGearRepository with
            | None ->
                ()
            | Some repository ->
                match CollectionState.getSelectedToneDefinition collectionState with
                | None ->
                    ()
                | Some tone ->
                    let ampGear =
                        getGearDataForCurrentPedal repository tone.GearList GearSlot.Amp
                        |> Option.get
                    let ampBar = knobProgressBar ampGear (Some tone.GearList.Amp)

                    TextBlock.create [
                        TextBlock.text (translate "Amp")
                        TextBlock.horizontalAlignment HorizontalAlignment.Center
                    ]

                    Border.create [
                        Border.margin (0., 2.)
                        Border.padding 6.
                        Border.background "#222"
                        Border.cornerRadius 4.
                        Border.child (
                            StackPanel.create [
                                StackPanel.children [
                                    TextBlock.create [
                                        TextBlock.text ampGear.Name
                                    ]

                                    let gainBar =
                                        [ "Gain"; "Vol 1"; "Volume" ]
                                        |> List.tryPick ampBar
                                        |> Option.orElseWith (fun () ->
                                            // Marshall Plexi has two loudness values
                                            let l1 = ampBar "Loudness 1"
                                            let l2 = ampBar "Loudness 2"

                                            Option.map2 List.append l1 l2)

                                    match gainBar with
                                    | Some g ->
                                        StackPanel.create [
                                            StackPanel.margin (10., 0.)
                                            StackPanel.children g
                                        ]
                                    | None ->
                                        ()
                                ]
                            ]
                        )
                    ]

                    yield!
                        [ ("PrePedals", GearSlot.PrePedal); ("LoopPedals", GearSlot.PostPedal); ("Rack",GearSlot.Rack) ]
                        |> List.collect (fun (name, func) ->
                            separator :: (pedals repository name tone.GearList func))
        ]
    ]

let view state dispatch collectionState =
    let dispatch' = ToneCollectionMsg >> dispatch

    Panel.create [
        Panel.children [
            hStack [
                TabControl.create [
                    TabControl.width 520.
                    TabControl.height 550.
                    TabControl.isEnabled collectionState.EditingUserTone.IsNone
                    TabControl.viewItems [
                        // Official tab
                        TabItem.create [
                            TabItem.header (translate "Official")
                            TabItem.content (
                                match collectionState.ActiveCollection with
                                | ActiveCollection.Official _ ->
                                    collectionView dispatch' collectionState
                                    |> generalize
                                | _ ->
                                    Panel.create [] |> generalize)
                            TabItem.onIsSelectedChanged (fun isSelected ->
                                if isSelected then
                                    ActiveTab.Official |> ChangeCollection |> dispatch'
                            )
                        ]

                        // User tab
                        TabItem.create [
                            TabItem.header (translate "User")
                            TabItem.content (
                                match collectionState.ActiveCollection with
                                | ActiveCollection.User _ ->
                                    collectionView dispatch' collectionState
                                    |> generalize
                                | _ ->
                                    Panel.create [] |> generalize)
                            TabItem.onIsSelectedChanged (fun isSelected ->
                                if isSelected then
                                    ActiveTab.User |> ChangeCollection |> dispatch'
                            )
                        ]
                    ]
                ]

                toneInfoPanel state collectionState
            ]

            match collectionState.EditingUserTone with
            | Some data ->
                Panel.create [
                    Panel.background "#343434"
                    Panel.children [ userToneEditor dispatch' data ]
                ]
            | None ->
                ()

            // Close Button
            Border.create [
                Border.cursor Cursors.hand
                Border.background Brushes.Transparent
                Border.horizontalAlignment HorizontalAlignment.Right
                Border.verticalAlignment VerticalAlignment.Top
                Border.focusable true
                Border.onTapped (fun _ -> dispatch (CloseOverlay OverlayCloseMethod.OverlayButton))
                Border.onKeyUp (fun args ->
                    if args.Key = Key.Space then
                        args.Handled <- true
                        dispatch (CloseOverlay OverlayCloseMethod.OverlayButton))
                Border.child (
                    Path.create [
                        Path.data Icons.x
                        Path.fill Brushes.DarkGray
                    ])
            ]
        ]
    ] |> generalize
