[<RequireQualifiedAccess>]
module ResizeArray

open System

/// Initializes a new ResizeArray with the given initial capacity.
let init (size: int) f =
    let a = ResizeArray(size)
    for i = 0 to size - 1 do a.Add(f i)
    a

/// Returns the element if the index is within the ResizeArray.
let inline tryItem index (a: ResizeArray<_>) =
    if index >= 0 && index < a.Count then
        Some a.[index]
    else
        None

/// Returns the last element in the ResizeArray or None if it is empty.
let inline tryLast (a: ResizeArray<_>) =
    if a.Count = 0 then
        None
    else
        Some a.[a.Count - 1]

/// Returns the first element in the ResizeArray or None if it is empty.
let inline tryHead (a: ResizeArray<_>) =
    if a.Count = 0 then None else Some a.[0]

/// Returns the first element that matches the predicate, or None if no match is found.
let tryFind (predicate: 'a -> bool) (a: ResizeArray<'a>) =
    let rec seek index =
        if index = a.Count then
            None
        else
            if predicate a.[index] then
                Some a.[index]
            else
                seek (index + 1)
    seek 0

/// Returns a new ResizeArray containing only the elements for which the predicate returns true.
let inline filter (predicate: 'a -> bool) (a: ResizeArray<'a>) : ResizeArray<'a> =
    a.FindAll(Predicate<_>(predicate))

/// Executes the action for each of the elements in the ResizeArray.
let iter action (a: ResizeArray<_>) =
    for i = 0 to a.Count - 1 do
        action a.[i]

/// Returns a ResizeArray that contains the single item.
let singleton (value: 'a) =
    let a = ResizeArray<'a>(1)
    a.Add(value)
    a

