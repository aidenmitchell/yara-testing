rule HTML_EXCESSIVE_PADDING {
    meta:
        author = "Aiden Mitchell"
        date = "2023-06-21"

    strings:
        $break1 = { 0D } // \r
        $break2 = { 0A } // \n
        $js_pattern = { 5F 30 78 } // _0x

    condition:
        (#break1 >= 100 or #break2 >= 100) and #js_pattern >= 50
}
