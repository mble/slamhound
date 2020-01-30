rule badthing
{
    meta:
        date = "2020-01-30"
    strings:
        $1 = "bad thing"
    condition:
        all of them and filename == "test.txt"
}
