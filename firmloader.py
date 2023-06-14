import os
import json
import idaapi
import idc
import ida_funcs
import ida_segment
import ida_segment
import ida_xref
import ida_bytes
import idautils
import ida_kernwin

class Firmloader(idaapi.action_handler_t):
    def __init__(self):
        idaapi.action_handler_t.__init__(self)


    def activate(self, ctx):
        found_rom = False
        rom_segment = 0
        for segment_ea in idautils.Segments():
                # Default ROM segment
                if idc.get_segm_name(segment_ea) == "ROM":
                    found_rom = True
                    rom_segment = segment_ea
        # If there is no ROM segment warn user and close
        if not found_rom:
            ida_kernwin.warning("Segment with name \"ROM\" does not exist. Please, rename the main code segment to \"ROM\" and run the plugin again.")
            return
        with open(os.path.join(os.path.dirname(os.path.realpath(__file__)),"firmloader_data",ctx.action + ".json")) as data_file:
            current_mcu = json.load(data_file)
            # Create segments
            for segment in current_mcu["segments"]:
                start = int(segment["start"],16)
                end = int(segment["end"],16)
                ida_segment.add_segm(0,start,end,segment["name"],segment["type"],0)
                # Set mode
            for segment_ea in idautils.Segments():
                # Set mode Thumb/ARM if ARM architecture
                if idaapi.get_inf_structure().procname == 'ARM' and found_rom:
                    idaapi.split_sreg_range(rom_segment, idaapi.str2reg("T"), current_mcu["mode"], idaapi.SR_user)
            # Create peripherals
            if ida_kernwin.ask_yn(1, "Would you like to load peripherals?"):
                for peripheral in current_mcu["peripherals"]:
                    # Start of the peripheral struct
                    start = int(peripheral["start"],16)
                    end = int(peripheral["end"],16)
                    ida_segment.add_segm(0,start,end,peripheral["name"],"DATA",0)
                    if peripheral["registers"]:
                        for register in peripheral["registers"]:
                            offset = int(register["offset"],16)
                            idc.set_name(start + offset, f'{peripheral["name"]}_{register["name"]}', idc.SN_NOCHECK)
                    # Add comment if any
                    idc.set_cmt(start,peripheral["comment"],False)
            # Crate vector table
            if current_mcu["vector_table"]:
                if ida_kernwin.ask_yn(1, "Would you like to also populate the vector table?"):
                    vector_address = ida_kernwin.ask_str(hex(rom_segment),0,"Set vector table at address:")
                    try:
                        if "x" in vector_address:
                            vector_address = int(vector_address,16)
                        else:
                            vector_address = int(vector_address)
                    except:
                        ida_kernwin.info("Invalid address!")
                        return
                    if not idc.get_segm_name(vector_address):
                        ida_kernwin.info("Invalid address!")
                        return
                    else:
                        for vector in current_mcu["vector_table"]:
                            # 
                            addr = vector_address + int(vector["addr"],16)
                            # Create a data value
                            if current_mcu["bits"] == 8:
                                ida_bytes.create_byte(addr,1)
                            elif current_mcu["bits"] == 16:
                                ida_bytes.create_qword(addr,2)
                            elif current_mcu["bits"] == 32:
                                ida_bytes.create_dword(addr,4)
                            elif current_mcu["bits"] == 64:
                                ida_bytes.create_qword(addr,8)

                            # Set name of the address
                            idc.set_name(addr, vector["name"]+"_vector", idc.SN_NOCHECK)
                            # Set comment
                            idc.set_cmt(addr,vector["comment"],False)
                            # Get XREF destination
                            destination = ida_bytes.get_32bit(addr)
                            # If ARM account for Thumb mode
                            if idaapi.get_inf_structure().procname == 'ARM' and destination % 2 == 1: # Thumb mode
                                destination = destination - 1
                            # If the segment is CODE
                            if ida_segment.get_segm_class(ida_segment.getseg(destination)) == "CODE":
                                # Create code reference
                                ida_xref.add_cref(addr,destination,1)
                                # If the name does not exist or is unk_*
                                if idc.get_name(destination) == "" or idc.get_name(destination).startswith("unk_"):
                                    ida_funcs.add_func(destination)
                                    idc.set_name(destination, vector["name"] + "_handler", idc.SN_NOCHECK | idc.SN_PUBLIC)
            # All is done at this point, mark the ROM segment for auto-analysis
            if found_rom:
                idc.auto_mark_range(rom_segment,idc.get_segm_end(rom_segment),idaapi.AU_WEAK) # Let IDA decide what is code and what is not

    # This action is always available.
    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS
    

class firmloader_t(idaapi.plugin_t):
    comment = "FirmLoader"
    help = "This script helps when working with various microcontroller firmware files."
    wanted_name = "FirmLoader"
    wanted_hotkey = ""
    flags = idaapi.PLUGIN_KEEP

    def init(self):
        for file_name in sorted(os.listdir(os.path.join(os.path.dirname(os.path.realpath(__file__)),"firmloader_data"))):
            #print(file_name)
            with open(os.path.join(os.path.dirname(os.path.realpath(__file__)),"firmloader_data",file_name)) as data_file:
                data = json.load(data_file)
                key = file_name.replace(".json","")
                if data["family"]:
                    menu_entry = "Edit/FirmLoader/"+ data["brand"] + "/" + data["family"] + "/"+ data["name"]
                else:
                    menu_entry = "Edit/FirmLoader/"+ data["brand"] + "/" + data["name"]
                action_desc = idaapi.action_desc_t(
                    key,   # The action name. This acts like an ID and must be unique
                    data["name"],  # The action text.
                    Firmloader(),   # The action handler.
                    '',      # Optional: the action shortcut
                    'Process firmware binary.'  # Optional: the action tooltip (available in menus/toolbar)
                    )           # Optional: the action icon (shows when in menus/toolbars)
                idaapi.register_action(action_desc)
                idaapi.attach_action_to_menu(menu_entry, key, idaapi.SETMENU_APP)

    def run(self):
        pass

    def term(self):
        pass

def PLUGIN_ENTRY():
    return firmloader_t()
