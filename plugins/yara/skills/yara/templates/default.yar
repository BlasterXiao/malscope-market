rule apt_{{CC}}_{{Group}}_{{Family}}_{{YYYYMMDDNN}} {
    meta:
        author = "{{author}}"
        copyright = "{{copyright}}"
        type = "APT"
        family = "{{Family}}"
        filetype = "exe"
        date = "{{date}}"
        last_modified = "{{last_modified}}"
        version = "1.0"
        score = 80
        reference = "*"
        md5 = "{{md5}}"
        description = "{{description}}"

    strings:
        {{strings}}

    condition:
        {{condition}}
}
