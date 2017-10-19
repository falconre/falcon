from binaryninja import *
import base64
import copy
import json


def falcon_export(bv) :
    filename = interaction.get_save_filename_input("Filename for Binja export")

    segments = []
    for segment in bv.segments :
        segments.append({
            'address': segment.start,
            'bytes': base64.b64encode(bv.read(segment.start, segment.length))
        })

    functions = []
    for function in bv.functions :
        functions.append({
            'name': function.name,
            'address': function.start,
        })


    fh = open(filename, 'wb')
    fh.write(json.dumps({
        'functions': functions,
        'segments': segments,
        'arch': bv.arch.name,
        'entry': bv.entry_point
    }))
    fh.close()


PluginCommand.register("Export for Falcon",
                       "Export disassembly information for Falcon",
                       falcon_export)