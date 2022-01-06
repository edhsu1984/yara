rule ExampleRule
{
    strings:
        $text_string = "ransome"
        $hex_string = { E2 34 A1 C8 23 FB }

    condition:
        $text_string or $hex_string
}
