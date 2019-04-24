{
    "targets": [
        {
            "target_name": "selectclientcert",
            "include_dirs": [
                "<!(node -e \"require('nan')\")"
            ],
            "sources": [
                "src/selectclientcert.cc"
            ],
            "conditions": [
                [
                    "OS == 'mac'",
                    {
                        "sources": [
                            "src/selectclientcert_mac.cc"
                        ]
                    }
                ],
                [
                    "OS == 'win'",
                    {
                        "sources": [
                            "src/selectclientcert_win.cc"
                        ],
                        "libraries": [
                            "crypt32.lib",
                            "cryptui.lib"
                        ]
                    }
                ],
                [
                    "OS not in ['mac','win']",
                    {
                        "sources": [
                            "src/selectclientcert_posix.cc"
                        ]
                    }
                ]
            ]
        }
    ]
}