#Add domain_os types/constants
#@author 
#@category Apollo
#@keybinding 
#@menupath Tools.Read Apollo Map File
#@toolbar 

import string
import re
import struct
from ghidra.program.model.symbol.SourceType import *
from ghidra.program.model.data import *
from ghidra.program.model.address import *

equateTable = currentProgram.getEquateTable()
dataTypes = currentProgram.getDataTypeManager()


def ensureEquate(name, value):
    if equateTable.getEquate(name) is None:
        equateTable.createEquate(name, value)

def add_types_and_equates():
    # make sure status_$t exists
    status_t = dataTypes.getDataType("status_$t")
    if status_t is None:
        status_t = dataTypes.addDataType(TypedefDataType("status_$t", UnsignedLongDataType()), DataTypeConflictHandler.DEFAULT_HANDLER)
        status_t_p = dataTypes.addDataType(PointerDataType(status_t), DataTypeConflictHandler.DEFAULT_HANDLER)

    uid_t = dataTypes.getDataType("uid_$t")
    if uid_t is None:
        uid_struct = StructureDataType("uid_$t", 0)
        uid_struct.add(UnsignedIntegerDataType(), 4, "high", None)
        uid_struct.add(UnsignedIntegerDataType(), 4, "low", None)
        uid_t = dataTypes.addDataType(uid_struct, DataTypeConflictHandler.DEFAULT_HANDLER)
        uid_t_p = dataTypes.addDataType(PointerDataType(uid_t), DataTypeConflictHandler.DEFAULT_HANDLER)

    # add all our status_$t equates
    ensureEquate("status_$ok",                  0x00000000)

    ensureEquate("bat_$block_already_freed",    0x00010001)
    ensureEquate("bat_$disk_full",              0x00010002)
    ensureEquate("bat_$illegal_disk_address",   0x00010003)
    ensureEquate("bat_$not_mounted",            0x00010004)
    ensureEquate("bat_$disk_needs_salvaging",   0x00010005)

    ensureEquate("vtoc_$not_mounted",           0x00020001)
    ensureEquate("vtoc_$bad_vtoc",              0x00020002)
    ensureEquate("vtoc_$no_file_map",           0x00020003)
    ensureEquate("vtoc_$no_uid",                0x00020004)
    ensureEquate("vtoc_$not_found",             0x00020005)
    ensureEquate("vtoc_$uid_not_found",         0x00020006)
    ensureEquate("vtoc_$duplicate_uid",         0x00020007)
    ensureEquate("vtoc_$uid_mismatch",          0x00020008)
    ensureEquate("vtoc_$only_local_access_allowed", 0x00020009)

    ensureEquate("ast_$address_not_found",      0x00030001)
    ensureEquate("ast_$no_replaceable_aste",    0x00030003)
    ensureEquate("ast_$segment_not_deactivatable", 0x00030004)
    ensureEquate("ast_$write_concurrency_violation", 0x00030005)
    ensureEquate("ast_$incompatible_request",   0x00030006)
    ensureEquate("ast_$reference_count_says_unused", 0x00030007)
    ensureEquate("ast_$segment_not_found_in_bst", 0x00030008)
    ensureEquate("ast_$segment_thread_error_in_bst", 0x00030009)
    ensureEquate("ast_$only_local_access_allowed", 0x0003000A)
    ensureEquate("ast_$system_object_cannot_be_deleted", 0x0003000B)

    ensureEquate("mst_$obj_not_found",          0x00040001)
    ensureEquate("mst_$invalid_length",        0x00040002)
    ensureEquate("mst_$no_space_available",    0x00040003)
    ensureEquate("mst_$reference_to_illegal_address", 0x00040004)
    ensureEquate("mst_$reference_to_out_of_bounds_address", 0x00040005)
    ensureEquate("mst_$no_asid_is_available",  0x00040006)
    ensureEquate("mst_$object_is_not_mapped",  0x00040007)
    ensureEquate("mst_$no_rights",             0x00040008)
    ensureEquate("mst_$insufficient_rights",   0x00040009)
    ensureEquate("mst_$guard_fault",           0x0004000A)
    ensureEquate("mst_$wrong_type",            0x0004000B)
    ensureEquate("mst_$ppn_list_overflow",     0x0004000C)
    ensureEquate("mst_$uid_mismatch",          0x0004000D)
    ensureEquate("mst_$virtual_memory_resources_exhausted", 0x0004000E)
    ensureEquate("mst_$invalid_va_for_install_of_io_page", 0x0004000F)
    ensureEquate("mst_$invalid_segment_count",  0x00040010)
    ensureEquate("mst_$asid_0_is_illegal_for_this_mapping", 0x00040011)

    ensureEquate("pmap_$not_allocated",        0x00050001)
    ensureEquate("pmap_$already_allocated",    0x00050002)
    ensureEquate("pmap_$mismatch",             0x00050003)
    ensureEquate("pmap_$bad_wire",             0x00050004)
    ensureEquate("pmap_$bad_unwire",           0x00050005)
    ensureEquate("pmap_$bad_assoc",            0x00050006)
    ensureEquate("pmap_$pages_wired",          0x00050007)
    ensureEquate("pmap_$page_null",            0x00050008)
    ensureEquate("pmap_$bad_disk_address",     0x00050009)
    ensureEquate("pmap_$read_concurrency_violation", 0x0005000A)
    ensureEquate("pmap_$changed_pmods",         0x0005000B)
    ensureEquate("pmap_$invalid_pmape",        0x0005000C)
    ensureEquate("pmap_$attempt_to_map_io_page_over_real_page", 0x0005000D)
    ensureEquate("pmap_$bst_threads_yielded_invalid_va", 0x0005000E)
    ensureEquate("pmap_$illegal_pid_argument_from_dxm_callback", 0x00050010)
    ensureEquate("pmap_$illegal_wsl_index",    0x00050011)
    
    ensureEquate("mmap_$bad_avail",            0x00060004)
    ensureEquate("mmap_$bad_free",             0x00060005)
    ensureEquate("mmap_$bad_unavail",          0x00060006)
    ensureEquate("mmap_$examined_max",         0x00060007)
    ensureEquate("mmap_$inconsistent_mmape",   0x00060008)
    ensureEquate("mmap_$illegal_wsl_index",    0x00060009)
    ensureEquate("mmap_$illegal_pid",          0x0006000A)
    ensureEquate("mmap_$ws_lists_exhsusted",   0x0006000B)
    ensureEquate("mmap_$bad_install",          0x0006000C)
    ensureEquate("mmap_$bad_reclaim",          0x0006000D)
    ensureEquate("mmap_$contiguous_pages_unavailable", 0x0006000E)

    ensureEquate("mmu_$miss",                  0x00070001)
    ensureEquate("mmu_$va_not_in_valid_mmu_manager_range", 0x00070002)
    ensureEquate("mmu_$va_does_not_have_os_pmap", 0x00070003)
    ensureEquate("mmu_$ptt_parity_error",       0x00070004)
    ensureEquate("mmu_$pft_parity_error",       0x00070005)
    ensureEquate("mmu_$timeout",               0x00070006)
    ensureEquate("mmu_$unknown_status",        0x00070007)
    ensureEquate("mmu_$parity_error",          0x00070008)
    ensureEquate("mmu_$data_cache_parity_error", 0x00070009)
    ensureEquate("mmu_$unexpected_virtual_timeout", 0x0007000A)
    ensureEquate("mmu_$write_buffer_timeout",   0x0007000B)

    # disk_$ equates
    ensureEquate("disk_$not_ready",             0x80001)
    ensureEquate("disk_$controller_busy",       0x80002)
    ensureEquate("disk_$controller_time_out",   0x80003)
    ensureEquate("disk_$controller_error",      0x80004)
    ensureEquate("disk_$equipment_check",       0x80005)
    ensureEquate("disk_$floppy_not_2_sided",    0x80006)
    ensureEquate("disk_$write_protected",       0x80007)
    ensureEquate("disk_$bad_format",            0x80008)
    ensureEquate("disk_$data_check",            0x80009)
    ensureEquate("disk_$dma_overrun",           0x8000a)
    ensureEquate("disk_$volume_in_use",         0x8000b)
    ensureEquate("disk_$volume_table_full",     0x8000c)
    ensureEquate("disk_$volume_not_mounted",    0x8000d)
    ensureEquate("disk_$operation_requires_physical_volume", 0x8000e)
    ensureEquate("disk_$invalid_volume_index",  0x8000f)
    ensureEquate("disk_$logical_volume_not_found", 0x80010)
    ensureEquate("disk_$block_header_error",    0x80011)
    ensureEquate("disk_$invalid_disk_address",  0x80012)
    ensureEquate("disk_$buffer_not_page_aligned", 0x80013)
    ensureEquate("disk_$invalid_logical_volume_index", 0x80014)
    ensureEquate("disk_$disk_seek_error",       0x80015)
    ensureEquate("disk_$drive_timed_out",       0x80016)
    ensureEquate("disk_$bus_error_during_disk_dma_transfer", 0x80017)
    ensureEquate("disk_$invalid_unit_number",   0x80018)
    ensureEquate("disk_$unknown_status_returned_by_hardware", 0x80019)
    ensureEquate("disk_$invalid_physical_volume_label", 0x8001a)
    ensureEquate("disk_$floppy_door_opened_or_storage_module_stopped", 0x8001b)
    ensureEquate("disk_$read_after_write_failed", 0x8001c)
    ensureEquate("disk_$dma_not_at_end_of_range", 0x8001d)
    ensureEquate("disk_$disk_already_mounted",  0x8001e)
    ensureEquate("disk_$software_detected_checksum_error", 0x8001f)
    ensureEquate("disk_$checksum_error_in_read_after_write", 0x80020)
    ensureEquate("disk_$too_many_wired_pages",  0x80021)
    ensureEquate("disk_$disk_driver_logic_error", 0x80022)
    ensureEquate("disk_$unknown_error_status_from_drive", 0x80023)
    ensureEquate("disk_$unrecognized_drive_id", 0x80024)
    ensureEquate("disk_$memory_parity_error_during_disk_write", 0x80025)
    ensureEquate("disk_$unrecognized_interrupt_from_disktape_controller", 0x80026)
    ensureEquate("disk_$ecc_error_in_sector_id_field", 0x80027)
    ensureEquate("disk_$disk_subsystem_detected_a_DC_powerfail", 0x80028)
    ensureEquate("disk_$transfer_not_executed", 0x80029)
    ensureEquate("disk_$illegal_request_for_device", 0x8002a)
    ensureEquate("disk_$unit_attention_presented_by_device", 0x8002b)
    ensureEquate("disk_$manufacturing_badspot_information_not_available_or_no_needed", 0x8002c)
    ensureEquate("disk_$disk_striping_not_yet_supported_on_this_device", 0x8002d)
    ensureEquate("disk_$queued_drivers_not_yet_supported_on_this_disk", 0x8002e)
    ensureEquate("disk_$disk_operation_completed_successfully_after_retry", 0x8002f)
    ensureEquate("disk_$disk_operation_completed_successfully_after_crc_correction", 0x80030)
    ensureEquate("disk_$disk_operation_completed_successfully_after_device_recovery", 0x80031)

    ensureEquate("ec_$bad_wait_list",           0x90001)

    ensureEquate("proc1_$illegal_pid",          0xa0001)
    ensureEquate("proc1_$illegal_lock",         0xa0002)
    ensureEquate("proc1_$not_suspended",        0xa0003)
    ensureEquate("proc1_$already_suspended",    0xa0004)
    ensureEquate("proc1_$not_bound",            0xa0005)
    ensureEquate("proc1_$already_bound",        0xa0006)
    ensureEquate("proc1_$bad_atomic_op",        0xa0007)
    ensureEquate("proc1_$no_pcb",               0xa0008)
    ensureEquate("proc1_$no_stack",             0xa0009)
    ensureEquate("proc1_$not_suspendable",      0xa000a)
    ensureEquate("proc1_$ready_list_out_of_order", 0xa000b)
    ensureEquate("proc1_$bad_deferred_interrupt_queue", 0xa000c)

    ensureEquate("term_$buffer_too_small",      0xb0001)
    ensureEquate("term_$end_of_file",           0xb0002)
    ensureEquate("term_$invalid_output_length", 0xb0003)
    ensureEquate("term_$invalid_option",        0xb0004)
    ensureEquate("term_$input_buffer_overrun",  0xb0005)
    ensureEquate("term_$async_fault",           0xb0006)
    ensureEquate("term_$invalid_line_number",   0xb0007)
    ensureEquate("term_$manual_stop",           0xb0008)
    ensureEquate("term_$char_framing_error",    0xb0009)
    ensureEquate("term_$char_parity_error",     0xb000a)
    ensureEquate("term_$dcd_changed",           0xb000b)
    ensureEquate("term_$cts_changed",           0xb000c)
    ensureEquate("term_$line_or_op_not_implemented", 0xb000d)
    ensureEquate("term_$hangup_fault",          0xb000e)
    ensureEquate("term_$speed_incompatible",    0xb000f)

    ensureEquate("dbuf_$bad_ptr",               0xc0001)
    ensureEquate("dbuf_$bad_free",              0xc0002)

    ensureEquate("time_$no_timer_queue_entry",  0xd0001)
    ensureEquate("time_$entry_to_be_cancelled_not_found", 0xd0002)
    ensureEquate("time_$quit_while_waiting_for_event", 0xd0003)
    ensureEquate("time_$bad_timer_interrupt",   0xd0004)
    ensureEquate("time_$bad_timer_key",         0xd0005)
    ensureEquate("time_$alarm_fault",           0xd0006)
    ensureEquate("time_$real_interval_timer_fault", 0xd0007)
    ensureEquate("time_$virtual_interval_timer_fault", 0xd0008)
    ensureEquate("time_$queue_element_not_in_use", 0xd0009)
    ensureEquate("time_$queue_element_not_found", 0xd000a)
    ensureEquate("time_$cpu_time_limit_exceeded", 0xd000b)
    ensureEquate("time_$time_adjustment_out_of_range", 0xd000c)
    ensureEquate("time_$queue_element_already_in_use", 0xd000d)
    ensureEquate("time_$relative_time_is_too_large", 0xd000e)

    ensureEquate("name_$directory_full",        0x000e0002)
    ensureEquate("name_$already_exists",        0x000e0003)
    ensureEquate("name_$bad_pathname",          0x000e0004)
    ensureEquate("name_$bad_link",              0x000e0005)
    ensureEquate("name_$not_link",              0x000e0006)
    ensureEquate("name_$not_found",             0x000e0007)
    ensureEquate("name_$ill_link_op",           0x000e000a)
    ensureEquate("name_$bad_leaf",              0x000e000b)
    ensureEquate("name_$node_unavailable",      0x000e000c)
    ensureEquate("name_$bad_directory",         0x000e000d)
    ensureEquate("name_$file_not_directory",    0x000e000e)
    ensureEquate("name_$directory_not_empty",   0x000e000f)
    ensureEquate("name_$not_file",              0x000e0010)
    ensureEquate("name_$ill_dir_op",            0x000e0011)
    ensureEquate("name_$bad_type",              0x000e0012)
    ensureEquate("name_$no_rights",             0x000e0013)
    ensureEquate("name_$insufficient_rights",   0x000e0014)
    ensureEquate("name_$is_sysboot",            0x000E0015)
    ensureEquate("name_$directory_in_use",      0x000E0016)
    ensureEquate("name_$replica_clock_skewed",  0x000E0017)
    ensureEquate("name_$ill_replica_request",   0x000E0018)
    ensureEquate("name_$no_replica_entry",      0x000E0019)
    ensureEquate("name_$last_entry",            0x000E001A)
    ensureEquate("name_$replica_deleted",       0x000E001B)
    ensureEquate("name_$replica_pkt_error",     0x000E001C)
    ensureEquate("name_$clocks_skewed",         0x000E001D)
    ensureEquate("name_$cant_find_replica",     0x000E001E)
    ensureEquate("name_$dir_must_be_root",      0x000E001F)
    ensureEquate("name_$dir_not_found",         0x000E0020)
    ensureEquate("name_$too_many_components",   0x000E0021)
    ensureEquate("name_$cache_entry_stale",     0x000E0022)
    ensureEquate("name_$cache_entry_updated",   0x000E0023)
    ensureEquate("name_$replica_uninitialized", 0x000E0024)
    ensureEquate("name_$internal_error",        0x000E0025)
    ensureEquate("name_$bad_req_hdr_version",   0x000E0026)
    ensureEquate("name_$bad_req_code",          0x000E0027)
    ensureEquate("name_$bad_req_body_version",  0x000E0028)
    ensureEquate("name_$request_ignored",       0x000E0029)
    ensureEquate("name_$dirs_not_neighbors",    0x000E002A)
    ensureEquate("name_$dir_not_local",         0x000E002B)
    ensureEquate("name_$pathname_truncated",    0x000E002C)
    ensureEquate("name_$leaf_truncated",        0x000E002D)
    ensureEquate("name_$bad_buffer_size",       0x000E002E)
    ensureEquate("name_$object_not_acl",        0x000E002F)
    ensureEquate("name_$vol_write_protected",   0x000E0030)
    ensureEquate("name_$dir_rcvr_w_protect",    0x000E0031)
    ensureEquate("name_$hard_link_overflow",    0x000E0032)
    ensureEquate("name_$dir_uid_not_found",     0x000E0033)
    ensureEquate("name_$insuff_memory",         0x000E0034)

    ensureEquate("file_$object_not_found",      0x000F0001)
    ensureEquate("file_$object_is_remote",      0x000F0002)
    ensureEquate("file_$bad_reply",             0x000F0003)
    ensureEquate("file_$comm_problem",          0x000F0004)
    ensureEquate("file_$object_not_locked",     0x000F0005)
    ensureEquate("file_$object_in_use",         0x000F0006)
    ensureEquate("file_$illegal_lock_req",      0x000F0007)
    ensureEquate("file_$lock_violation",        0x000F0008)
    ensureEquate("file_$local_lock_table_full", 0x000F0009)
    ensureEquate("file_$remote_lock_table_full", 0x000F000A)
    ensureEquate("file_$op_cant_be_done",       0x000F000B)
    ensureEquate("file_$no_more_lock_entries",  0x000F000C)
    ensureEquate("file_$vol_uid_unavail",       0x000F000D)
    ensureEquate("file_$locking_blocked",       0x000F000E)
    ensureEquate("file_$locking_already_blocked", 0x000F000F)
    ensureEquate("file_$no_rights",             0x000F0010)
    ensureEquate("file_$insufficient_rights",   0x000F0011)
    ensureEquate("file_$wrong_type",            0x000F0012)
    ensureEquate("file_$objects_on_diff_vols",  0x000F0013)
    ensureEquate("file_$invalid_arg",           0x000F0014)
    ensureEquate("file_$incompatible_req",      0x000F0015)
    ensureEquate("file_$vol_read_only",         0x000F0016)

    ensureEquate("io_$ctrlr_not_found",         0x00010001)
    ensureEquate("io_$ctrlr_not_in_system",     0x00010002)
    ensureEquate("io_$illegal_int_id",          0x00010003)
    ensureEquate("io_$int_id_already_in_use",   0x00010004)
    ensureEquate("io_$int_id_not_implemented",  0x00010005)
    ensureEquate("io_$int_id_table_full",       0x00010006)
    ensureEquate("io_$bad_dcte_length",         0x00010007)
    ensureEquate("io_$illegal_unit_num",        0x00010008)
    ensureEquate("io_$unit_not_acquired",       0x00010009)
    ensureEquate("io_$unit_already_in_use",     0x0001000A)
    ensureEquate("io_$unit_table_full",         0x0001000B)
    ensureEquate("io_$illegal_csr_addr",        0x0001000C)
    ensureEquate("io_$int_id_already_in_use",   0x0001000D)
    ensureEquate("io_$csr_page_already_in_use", 0x0001000E)
    ensureEquate("io_$csr_addr_already_mapped", 0x0001000F)
    ensureEquate("io_$io_map_full",             0x00010010)
    ensureEquate("io_$device_failed_self_test", 0x00010011)
    ensureEquate("io_$boot_device_not_found",   0x00010012)
    ensureEquate("io_$int_stack_error",         0x00010013)

    ensureEquate("network_$buffer_error",       0x00110001)
    ensureEquate("network_$out_of_pages",       0x00110002)
    ensureEquate("network_$out_of_blocks",      0x00110003)
    ensureEquate("network_$transmit_failed",    0x00110004)
    ensureEquate("network_$no_avail_socket",    0x00110005)
    ensureEquate("network_$buffer_queue_empty", 0x00110006)
    ensureEquate("network_$no_remote_response", 0x00110007)
    ensureEquate("network_unable_to_route",     0x00110008)
    ensureEquate("network_$hardware_error",     0x00110009)
    ensureEquate("network_$msg_header_too_big", 0x0011000A)
    ensureEquate("network_$unexpected_reply_type", 0x0011000B)
    ensureEquate("network_$no_more_free_sockets", 0x0011000C)
    ensureEquate("network_$unknown_request_type", 0x0011000D)
    ensureEquate("network_$request_denied_by_local_node", 0x0011000E)
    ensureEquate("network_$request_denied_by_remote_node", 0x0011000F)
    ensureEquate("network_$bad_checksum",       0x00110010)
    ensureEquate("network_$too_many_transmit_retries", 0x00110011)
    ensureEquate("network_$socket_not_open",    0x00110012)
    ensureEquate("network_$receive_bus_error",  0x00110013)
    ensureEquate("network_$transmit_bus_error", 0x00110014)
    ensureEquate("network_$bad_asknode_version_number", 0x00110015)
    ensureEquate("network_$memory_parity_error_during_transmit", 0x00110016)
    ensureEquate("network_$unknown_network",    0x00110017)
    ensureEquate("network_$too_many_networks_in_internet", 0x00110018)
    ensureEquate("network_$conflict_with_another_node_listing", 0x00110019)
    ensureEquate("network_$quit_fault_during_node_listing", 0x0011001A)
    ensureEquate("network_$waited_too_long_for_more_nodes_to_respond", 0x0011001B)
    ensureEquate("network_$data_length_too_large", 0x0011001C)
    ensureEquate("network_$operation_not_defined_on_network_hardware", 0x0011001D)
    ensureEquate("network_$header_length_plus_data_length_exceeds_max_msg_size", 0x0011001E)
    ensureEquate("network_$no_nodeid_prom_on_this_system", 0x0011001F)
    ensureEquate("network_$device_stat_block_is_not_valid", 0x00110020)
    ensureEquate("network_$device_stat_selection_index_is_out_of_range", 0x00110021)
    ensureEquate("network_$foreign_node_does_not_support_all_network_features", 0x00110022)
    ensureEquate("network_$attempt_to_transmit_with_invalid_FROM_ID", 0x00110023)
    ensureEquate("network_$header_data_length_exceeds_max_size_allowed", 0x00110024)

    ensureEquate("fault_$odd_address",          0x120001)
    ensureEquate("fault_$illegal_instruction",  0x120002)
    ensureEquate("fault_$integer_divide_by_zero", 0x120003)
    ensureEquate("fault_$chk_instruction_trapped", 0x120004)
    ensureEquate("fault_$arithmetic_overflow",  0x120005)
    ensureEquate("fault_$privileged_instruction_violation", 0x120006)
    ensureEquate("fault_$invalid_svc_code",     0x120007)
    ensureEquate("fault_$invalid_svc_procedure_name", 0x120008)
    ensureEquate("fault_$undefined_trap_instruction", 0x120009)
    ensureEquate("fault_$unimplemented_instruction", 0x12000A)
    ensureEquate("fault_$protection_boundary_violation", 0x12000B)
    ensureEquate("fault_$bus_time_out",         0x12000C)
    ensureEquate("fault_$invalid_user_stack_pointer", 0x12000D)
    ensureEquate("fault_$correctable_memory_error_detected", 0x12000E)
    ensureEquate("fault_$uncorrectable_memory_error_detected", 0x12000F)
    ensureEquate("fault_$process_quit",         0x120010)
    ensureEquate("fault_$access_violation",    0x120011)
    ensureEquate("fault_$cpu_b_enabled_with_mmu_valid_bit_reset", 0x120012)
    ensureEquate("fault_$null_process_running_on_cpu_b", 0x120013)
    ensureEquate("fault_$os_internal_quit_with_display_return", 0x120014)
    ensureEquate("fault_$single_step_completed", 0x120015)
    ensureEquate("fault_$invalid_user_generated_fault", 0x120016)
    ensureEquate("fault_$fault_in_user_space_interrupt_handler_for_pbu_device", 0x120017)
    ensureEquate("fault_$process_stop",         0x120018)
    ensureEquate("fault_$process_blast",        0x120019)
    ensureEquate("fault_$cache_parity_error",   0x12001A)
    ensureEquate("fault_$peb_wcs_parity_error", 0x12001B)
    ensureEquate("fault_$unimplemented_svc",   0x12001C)
    ensureEquate("fault_$invalid_stack_format", 0x12001D)
    ensureEquate("fault_$memory_parity_error",  0x12001E)
    ensureEquate("fault_$process_interrupt",    0x12001F)
    ensureEquate("fault_$supervisor_fault_while_resource_locks_set", 0x120020)
    ensureEquate("fault_$spurious_parity_error", 0x120021)
    ensureEquate("fault_$floating_point_inexact_result", 0x120022)
    ensureEquate("fault_$floating_point_divide_by_zero", 0x120023)
    ensureEquate("fault_$floating_point_underflow", 0x120024)
    ensureEquate("fault_$floating_point_operand_error", 0x120025)
    ensureEquate("fault_$floating_point_overflow", 0x120026)
    ensureEquate("fault_$process_suspend_fault", 0x120027)
    ensureEquate("fault_$process_suspend_from_keyboard", 0x120028)
    ensureEquate("fault_$process_suspend_due_to_background_read", 0x120029)
    ensureEquate("fault_$process_suspend_due_to_background_write", 0x12002A)
    ensureEquate("fault_$process_continue_fault", 0x12002B)
    ensureEquate("fault_$faults_lost", 0x12002C)
    ensureEquate("fault_$coprocessor_protocol_violation", 0x12002D)
    ensureEquate("fault_$floating_point_branch_set_on_unordered_condition", 0x12002E)
    ensureEquate("fault_$floating_point_signalling_nan", 0x12002F)
    ensureEquate("fault_$invalid_thread_during_parity_error_check", 0x120030)
    ensureEquate("fault_$illegal_page_fault_in_user_gpio_interrupt_routine", 0x120031)
    ensureEquate("fault_$bus_error_while_running_on_cpu_b", 0x120032)
    ensureEquate("fault_$spurious_interrupt", 0x120033)
    ensureEquate("fault_$unexpected_bus_error_during_system_initialization", 0x120034)
    ensureEquate("fault_$cleanup_handler_set", 0x120035)
    ensureEquate("fault_$cleanup_handler_released_out_of_order", 0x120036)
    ensureEquate("fault_$ac_power_failure", 0x120037)
    ensureEquate("fault_$fpx_parity_error", 0x120038)
    ensureEquate("fault_$unknown_fpa_exception", 0x120039)
    ensureEquate("fault_$vme_bus_error_on_bus_error", 0x12003A)
    ensureEquate("fault_$at_bus_parity_error_io_channel_chk", 0x12003B)
    ensureEquate("fault_$breakpoint", 0x12003C)
    ensureEquate("fault_$translate_error", 0x12003D)
    ensureEquate("fault_$illegal_lock", 0x12003E)
    ensureEquate("fault_$lock_timeout", 0x12003F)
    ensureEquate("fault_$unknown_status", 0x120040)
    ensureEquate("fault_$floating_point_exception", 0x120041)
    ensureEquate("fault_$a88k_fpu_internal_error", 0x120042)
    ensureEquate("fault_$pause_interrupt_received_by_cpu", 0x120043)
    ensureEquate("fault_$halt_interrupt_received_by_cpu", 0x120044)
    ensureEquate("fault_$trap_occurred_while_already_in_trap_mode", 0x120045)
    ensureEquate("fault_$unaligned_instruction", 0x120046)
    ensureEquate("fault_$floating_point_hardware_error_incorrect_data_stored_to_memory", 0x120047)
    ensureEquate("fault_$integer_processor_hardware_error_incorrect_data_stored_to_memory", 0x120048)
                             
    ensureEquate("smd_$operation_ok",         0x00000000)
    ensureEquate("smd_$illegal_unit",         0x00130001)
    ensureEquate("smd_$font_not_loaded",      0x00130002)
    ensureEquate("smd_$font_table_full",      0x00130003)
    ensureEquate("smd_$illegal_caller",       0x00130004)
    ensureEquate("smd_$font_too_large",       0x00130005)
    ensureEquate("smd_$hdmt_unload_err",      0x00130006)
    ensureEquate("smd_$illegal_direction",    0x00130007)
    ensureEquate("smd_$unexp_blt_inuse",      0x00130008)
    ensureEquate("smd_$protocol_viol",        0x00130009)
    ensureEquate("smd_$too_many_pages",       0x0013000A)
    ensureEquate("smd_$unsupported_font_ver", 0x0013000B)
    ensureEquate("smd_$invalid_buffer_size",  0x0013000C)
    ensureEquate("smd_$display_map_error",    0x0013000D)
    ensureEquate("smd_$borrow_error",         0x0013000E)
    ensureEquate("smd_$display_in_use",       0x0013000F)
    ensureEquate("smd_$access_denied",        0x00130010)
    ensureEquate("smd_$return_error",         0x00130011)
    ensureEquate("smd_$not_borrowed",         0x00130012)
    ensureEquate("smd_$cant_borrow_both",     0x00130013)
    ensureEquate("smd_$already_borrowed",     0x00130014)
    ensureEquate("smd_$invalid_pos",          0x00130015)
    ensureEquate("smd_$invalid_window",       0x00130016)
    ensureEquate("smd_$invalid_length",       0x00130017)
    ensureEquate("smd_$invalid_direction",    0x00130018)
    ensureEquate("smd_$invalid_displacement", 0x00130019)
    ensureEquate("smd_$invalid_blt_mode",     0x0013001A)
    ensureEquate("smd_$invalid_blt_ctl",      0x0013001B)
    ensureEquate("smd_$invalid_bltd_int",     0x0013001C)
    ensureEquate("smd_$invalid_ir_state",     0x0013001D)
    ensureEquate("smd_$invalid_blt_coord",    0x0013001E)
    ensureEquate("smd_$font_not_mapped",      0x0013001F)
    ensureEquate("smd_$already_mapped",       0x00130020)
    ensureEquate("smd_$not_mapped",           0x00130021)
    ensureEquate("smd_$quit_while_waiting",   0x00130022)
    ensureEquate("smd_$invalid_crsr_number",  0x00130023)
    ensureEquate("smd_$hdm_full",             0x00130024)
    ensureEquate("smd_$wait_quit",            0x00130025)
    ensureEquate("smd_$invalid_key",          0x00130026)
    ensureEquate("smd_$not_on_color",         0x00130027)
    ensureEquate("smd_$not_implemented",      0x00130028)
    ensureEquate("smd_$invalid_wid",          0x00130029)
    ensureEquate("smd_$window_obscured",      0x0013002A)
    ensureEquate("smd_$no_more_wids",         0x0013002B)
    ensureEquate("smd_$process_not_found",    0x0013002C)
    ensureEquate("smd_$disp_acqd",            0x0013002D)
    ensureEquate("smd_$already_acquired",     0x0013002E)
    ensureEquate("smd_$acquire_timeout",      0x0013002F)
    ensureEquate("smd_$bad_tracking_rect",    0x00130030)
    ensureEquate("smd_$trkng_list_full",      0x00130031)
    ensureEquate("smd_$no_hidden_memory",     0x00130032)
    ensureEquate("smd_$not_being_used_by_process",       0x00130033)
    ensureEquate("smd_$process_terminated",   0x00130034)

    ensureEquate("vol_$disk_write_protected", 0x14ffff)
    ensureEquate("vol_$entry_dir_problem",    0x140001)
    ensureEquate("vol_$unable_to_dismount_boot_vol",   0x140002)
    ensureEquate("vol_$logical_vol_not_mounted", 0x140003)
    ensureEquate("vol_$entry_dir_not_on_logical_vol", 0x140004)
    ensureEquate("vol_$phys_vol_replaced_since_mount", 0x140005)

    ensureEquate("cal_$syntax_error",          0x150001)
    ensureEquate("cal_$invalid_date_or_time",  0x150002)
    ensureEquate("cal_$empty_string",          0x150003)
    ensureEquate("cal_$unknown_timezone",      0x150004)
    ensureEquate("cal_$invalid_timezone_diff", 0x150005)

    ensureEquate("xpd_$local_target_spans_mult_objs", 0x160001)
    ensureEquate("xpd_$local_target_spans_discontig_segs", 0x160002)
    ensureEquate("xpd_$invalid_state_arg",     0x160003)
    # 160004?
    ensureEquate("xpd_$not_a_debugger",       0x160005)
    ensureEquate("xpd_$debugger_not_found",   0x160006)
    ensureEquate("xpd_$debugger_table_full",  0x160007)
    ensureEquate("xpd_$req_state_inapplicable_to_mach_type", 0x160008)
    ensureEquate("xpd_$already_a_debugger",   0x160009)
    ensureEquate("xpd_$target_proc_not_found", 0x16000A)
    ensureEquate("xpd_$no_event_posted_for_target_not_suspended", 0x16000B)
    ensureEquate("xpd_$invalid_ec_key",       0x16000C)
    ensureEquate("xpd_$locate_target_has_var_mmu_access", 0x16000D)
    ensureEquate("xpd_$state_unavail_for_this_event", 0x16000E)
    ensureEquate("xpd_$invalid_ctrl_inquire_option", 0x16000F)
    ensureEquate("xpd_$mutually_exclusive_ctrl_opts", 0x160010)
    ensureEquate("xpd_$superfluous_or_illegal_target_setup", 0x160011)
    ensureEquate("xpd_$target_proc_is_forking", 0x160012)
    ensureEquate("xpd_$target_proc_is_execing_a_prog", 0x160013)
    ensureEquate("xpd_$target_proc_is_invoking_a_prog", 0x160014)
    ensureEquate("xpd_$target_proc_is_exiting", 0x160015)
    ensureEquate("xpd_$target_proc_is_loading_an_exec_img", 0x160016)
    ensureEquate("xpd_$target_proc_is_vforking", 0x160017)

    ensureEquate("dxm_$no_more_slots",         0x170001)
    ensureEquate("dxm_$datum_too_large",      0x170002)
    ensureEquate("dxm_$wired_helper_not_supported", 0x170003)
    
    ensureEquate("ec2_$internal_table_exhausted", 0x180001)
    ensureEquate("ec2_$internal_error",        0x180002)
    ensureEquate("ec2_$async_fault",           0x180003)
    ensureEquate("ec2_$bad_eventcount",        0x180004)
    ensureEquate("ec2_$unable_to_allocate_level_1_eventcount", 0x180005)
    ensureEquate("ec2_$level_1_eventcount_not_allocated", 0x180006)

    ensureEquate("proc2_$proc_not_found",      0x190001)
    ensureEquate("proc2_$not_level_2_proc",    0x190002)
    ensureEquate("proc2_$bad_stack_base",      0x190003)
    ensureEquate("proc2_$request_for_current_proc", 0x190004)
    ensureEquate("proc2_$suspend_timeout",     0x190005)
    ensureEquate("proc2_$proc_not_suspended",  0x190006)
    ensureEquate("proc2_$proc_already_suspended", 0x190007)
    ensureEquate("proc2_$child_proc_terminated", 0x190008)
    ensureEquate("proc2_$another_fault_pending", 0x190009)
    ensureEquate("proc2_$invalid_proc_name",   0x19000A)
    ensureEquate("proc2_$bad_eventcount_key",  0x19000B)
    ensureEquate("proc2_$vfork_on_non_vforked_proc", 0x19000C)
    ensureEquate("proc2_$wait_found_no_children", 0x19000D)
    ensureEquate("proc2_$proc_is_zombie",      0x19000E)
    ensureEquate("proc2_$no_entries_in_proc_table", 0x19000F)
    ensureEquate("proc2_$proc_not_debug_target", 0x190010)
    ensureEquate("proc2_$proc_already_debug_target", 0x190011)
    ensureEquate("proc2_$permission_denied",   0x190012)
    ensureEquate("proc2_$internal_error",      0x190013)
    ensureEquate("proc2_$proc_already_orphan", 0x190014)
    ensureEquate("proc2_$proc_is_proc_group_leader", 0x190015)
    ensureEquate("proc2_$another_proc_using_proc_group_id", 0x190016)
    ensureEquate("proc2_$attempted_to_join_proc_group_in_diff_session", 0x190017)

#           OS / import/export manager
# (1a0001)   entry directory is not cataloged in the namespace
# (1a0002)   files are locked on this volume
# (1a0003)   specified entry directory not on this volume
# (1a0004)   volume is not mounted

#           OS / startup/shutdown
# (1b0001)   node ID mismatch
# (1b0002)   checksumming already enabled
# (1b0003)   no os paging file -- please run invol option 8
# (1b0004)   no calendar on system -- please boot over network
# (1b0005)   CPU board below minimum revision level
# (1b0006)   undefined interrupt
# (1b0007)   cold start error
# (1b0008)   system reboot
# (1b0009)   exception handler is not longword-aligned
# (1b000a)   cpu has unexpected cpu id in vbr reg
# (1b000b)   timeout waiting for cpus to start

#           OS / vfmt
# (1c0001)   unterminated control string
# (1c0002)   invalid control string
# (1c0003)   too few arguments supplied for read/decode
# (1c0004)   field width missing on "(" designator
# (1c0005)   encountered end of string where more text expected
# (1c0006)   encountered null token where numeric token expected
# (1c0007)   non-numeric character found where numeric was expected
# (1c0008)   sign encountered in unsigned field
# (1c0009)   value out of range in text string
# (1c000a)   character in text string does not match control string
# (1c000b)   terminator in text string does not match specified terminator

#           OS / circular buffer manager
# (1d0001)   invalid block size requested
# (1d0002)   quit while waiting
# (1d0003)   buffer wrap-around error

#           OS / pbu manager
# (1e0001)   ddf is larger then expected
# (1e0002)   ddf has wrong version
# (1e0003)   invalid unit number in ddf
# (1e0004)   invalid csr page address in ddf
# (1e0005)   csr page is in use
# (1e0006)   initialization routine not in library
# (1e0007)   cleanup routine not in library
# (1e0008)   interrupt library too large
# (1e0009)   interrupt routine not in library
# (1e000a)   pbu not present
# (1e000b)   too many pbu manager pages wired
# (1e000c)   invalid unit number
# (1e000d)   unit in use
# (1e000e)   unit not acquired
# (1e000f)   unit already acquired
# (1e0010)   bad parameter
# (1e0011)   no room in iomap
# (1e0012)   requested iomap in use
# (1e0013)   iomap already allocated
# (1e0014)   iomap not allocated
# (1e0015)   invalid iova
# (1e0016)   buffer too large
# (1e0017)   buffer page not wired
# (1e0018)   buffer not mapped
# (1e0019)   page already wired
# (1e001a)   page wired too many times
# (1e001b)   page not wired
# (1e001c)   reference to csr page caused bus timeout
# (1e001d)   trap 6 executed outside of interrupt routine
# (1e001e)   invalid trap 6 code
# (1e001f)   invalid usp at trap 6
# (1e0020)   protection violation
# (1e0021)   unexpected interrupt from pbu device
# (1e0022)   ddf has wrong file type
# (1e0023)   too many wired pages
# (1e0024)   csr not in device's csr page
# (1e0025)   controller already mapped
# (1e0026)   bad controller memory length
# (1e0027)   bad buffer address
# (1e0028)   interrupt library not found
# (1e0029)   device library not found
# (1e002a)   device is not a shared controller
# (1e002b)   device not mapped
# (1e002c)   pbu device got bus timeout on multibus
# (1e002d)   all pbu units in use
# (1e002e)   wrong version of /lib/pbulib in use
# (1e002f)   interrupt level in use
# (1e0030)   operation valid only for VME device
# (1e0031)   physical address list too small
# (1e0032)   function not supported for this device type
# (1e0033)   illegal dma channel number
# (1e0034)   bad dma direction specified
# (1e0035)   requested dma channel in use
# (1e0036)   requested dma channel not in use
# (1e0037)   dma channel not at end of range
# (1e0038)   no more eventcounts available
# (1e0039)   eventcount not allocated to this unit
# (1e003a)   unit already in use as a global device
# (1e003b)   unit is publicly owned
# (1e003c)   buffer pages not physically contiguous
# (1e003d)   contiguous buffer not page aligned

#           OS / line printer module
# (1f0001)   pna board not installed in system
# (1f0002)   invalid string length
# (1f0003)   invalid string termination
# (1f0004)   line printer not acquired
# (1f0005)   line printer already acquired
# (1f0006)   internal error
# (1f0007)   ppn list overflow - internal error
# (1f0008)   line printer not assigned
# (1f0009)   no line printer on system

#           OS / OS info supplier
# (200001)   array too small for complete table

#           OS / badspot manager
# (210001)   bad checksum in physical badspot block
# (210002)   bad count in physical badspot block
# (210003)   missing minus-one in physical badspot block
# (210004)   badspot list too small
# (210005)   no physical badspot blocks read or written
# (210006)   physical badspot list partially read or written
# (210007)   duplicate entry in badspot list
# (210008)   no physical badspot information on disk
# (210009)   bad daddr for lv label badspot extension block
# (21000a)   too many extensions to lv badspot list
# (21000b)   badspot extension uid <> logical volume uid
# (21000c)   manufacturer badspot list is corrupt
# (21000d)   illegal physical badspot list address specified

#           OS / magtape manager
# (22fffe)   warning: tape not at load-point
# (22ffff)   warning: tape unit is offline
# (220001)   invalid mt unit number
# (220002)   invalid mode field
# (220003)   invalid buffer length
# (220004)   invalid parameter
# (220005)   no PNA board installed in system
# (220006)   magtape unit is not connected
# (220007)   magtape not acquired
# (220008)   magtape unit is not ready
# (220009)   unit will not fit thru 25" hatch
# (22000a)   magtape unit in use
# (22000b)   magtape not initialized
# (22000c)   magtape already acquired
# (22000d)   invalid option
# (22000e)   too many outstanding operations
# (22000f)   invalid buffer address
# (220010)   invalid count for erase or space operation
# (220011)   tape drive is hung
# (220012)   ppn list overflow - internal error
# (220013)   config page in use - internal error
# (220014)   release problems - internal error
# (220015)   unexpected interrupt
# (220016)   operation attempted before waiting
# (220017)   wait attempted before go issued
# (220018)   go command issued while not in batch mode
# (220019)   header or buffer misalignment on chained r/w
# (22001a)   user quit while in mt_$wait
# (22001b)   timeout during wait or release
# (22001c)   header buffer not on header page
# (22001d)   no room from mt_$write - internal error
# (22001e)   info array (passed to mt_$wait) too small
# (22001f)   too many pages wired
# (220020)   too many pbu devices in use
# (220021)   buffer already wired
# (220022)   buffer not wired

#           OS / ACL manager
# (230001)   no right to perform operation
# (230002)   insufficient rights to perform operation
# (230003)   exit_super called more often than enter_super
# (230004)   wrong type - operation illegal on system objects
# (230005)   entry already exists
# (230006)   ACL is remote
# (230007)   ACL is on different volume than object
# (230008)   ACL protects wrong type of object
# (230009)   insufficient address space to open ACL
# (23000a)   required entry may not be deleted
# (23000b)   no entry - entry number too large
# (23000c)   image buffer too small or incorrect size
# (23000d)   ACL object not found
# (23000e)   ACL would be unchangeable
# (23000f)   object may not be readable by backup procedure
# (230010)   no right to set subsystem data or subsystem manager
# (230011)   project list is full - no more entries may be added
# (230012)   project list is too big - it cannot be added to object
# (230013)   ACL is full - no more entries may be added
# (230014)   Unused ACL status code
# (230015)   Unused ACL status code
# (230016)   Unused ACL status code
# (230017)   Unused ACL status code
# (230018)   Unused ACL status code
# (230019)   Unused ACL status code
# (23001a)   Unused ACL status code
# (23001b)   required entry missing from ACL
# (23001c)   attempt to issue unimplemented ACL call
# (23001d)   invalid selection for required entry
# (23001e)   invalid required entry
# (23001f)   may only setid to required entry
# (230020)   may not use setid in a default acl
# (230021)   invalid right supplied

#           OS / PEB manager
# (240001)   fpu is hung
# (240002)   PEB interrupt
# (240003)   floating point overflow
# (240004)   floating point underflow
# (240005)   divide by zero
# (240006)   floating point loss of significance
# (240007)   floating point hardware error
# (240008)   attempted use of unimplemented opcode
# (240009)   wcs verify failed

#           OS / network logging manager
# (250001)   ppn list overflow

#           OS / color display manager
# (260001)   illegal caller
# (260002)   too many wired pages
# (260003)   virtual address not page aligned in color_$map
# (260004)   pages unmapped out of order
# (260005)   parameter value out of range
# (260006)   color display not available
# (260007)   instruction queue done wait timed out

#           OS / vme bus manager
# (270001)   undefined vme interrupt
# (270002)   vme bus error
# (270003)   ubus error caused by vme bus
# (270004)   iomap parity error
# (270005)   timeout on vme bus

#           OS / cartridge tape manager
# (28fffa)   warning: tape in write mode
# (28fffb)   warning: tape in read mode
# (28fffc)   warning: tape not at load-point
# (28fffd)   tape at load point
# (28fffe)   warning: tape unit is offline
# (28ffff)   tape power on/reset
# (280001)   invalid ct unit number
# (280002)   unit not acquired
# (280003)   unit already acquired
# (280004)   unit in use
# (280005)   no tape controller on system
# (280006)   invalid buffer length
# (280007)   bad buffer alignment
# (280008)   invalid buffer address
# (280009)   unrecognized action type
# (28000a)   invalid operation count
# (28000b)   unit not ready
# (28000c)   unexpected ct interrupt
# (28000d)   quit waiting for i/o
# (28000e)   timeout waiting for i/o
# (28000f)   too many wired pages
# (280010)   no cartridge in drive
# (280011)   drive does not exist
# (280012)   tape is write protected
# (280013)   end of tape
# (280014)   read/write abort
# (280015)   read block error
# (280016)   read filler error
# (280017)   read no data
# (280018)   read no data and end of tape
# (280019)   read no data and load point
# (28001a)   filemark detected
# (28001b)   illegal drive command
# (28001c)   marginal block detected
# (28001d)   unrecognized drive status
# (28001e)   dma not at end of range
# (28001f)   dma underrun/overrun
# (280020)   memory parity error during dma
# (280021)   illegal controller command
# (280022)   controller timeout
# (280023)   controller diagnostic failed
# (280024)   unrecognized controller status
# (280025)   operation already in progress
# (280026)   operation not in progress

#           OS / msg manager
# (290001)   socket out of range
# (290002)   too deep
# (290003)   socket error
# (290004)   no more sockets
# (290005)   not owner
# (290006)   too much data
# (290007)   socket empty
# (290008)   socket in use
# (290009)   time out
# (29000a)   quit fault

#           OS / symbolic link manager
# (2a0001)   file not symbolic link type
# (2a0002)   bad symbolic link file

#           OS / internet routing
# (2b0001)   network port not open
# (2b0002)   buffer queue for user port is full
# (2b0003)   unknown network port
# (2b0004)   can not create/delete that port type
# (2b0005)   max number of ports already open
# (2b0006)   routing service type not recognized
# (2b0007)   port belongs to another process
# (2b0008)   routing through-traffic queue overflow
# (2b0009)   operation not legal on this port type
# (2b000a)   unknown network device type
# (2b000b)   no more buffer queues for user networks
# (2b000c)   user network checksum failed
# (2b000d)   bad packet length from user network
# (2b000e)   unable to create through-traffic queue
# (2b000f)   max number of USER ports already open
# (2b0010)   bad request type asking for service change
# (2b0011)   routing not allowed at port with 0 network ID

#           OS / internet interface controller
# (2c0001)   IIC: dma got multibus read timeout error
# (2c0002)   IIC: not initialized prior to operation
# (2c0003)   IIC: transmitter underrun error
# (2c0004)   IIC: undocumented interrupt raised
# (2c0005)   IIC: hardware reset operation timed out
# (2c0006)   IIC: self test failure reported by board init
# (2c0007)   device already acquired
# (2c0008)   device not acquired
# (2c0009)   operation aborted
# (2c000a)   device not in system
# (2c000b)   remote device not acquired
# (2c000c)   could get expected packet from receive socket
# (2c000d)   could not allocate receive socket for device
# (2c000e)   never got expected command completion interrupt
# (2c000f)   wrong board revision level
# (2c0010)   invalid command control block
# (2c0011)   invalid receive control block

#           OS / graphics processor manager
# (2d0001)   device not present in system
# (2d0002)   device not available
# (2d0003)   package not initialized
# (2d0004)   package already initialized
# (2d0005)   device not ready for PIO
# (2d0006)   device timeout
# (2d0007)   wait terminated by process fault
# (2d0008)   error condition reported by GPU
# (2d0009)   page fault interrupt
# (2d000a)   illegal values for physical page use limits
# (2d000b)   Programmed I/O command error
# (2d000c)   DMA command execution error
# (2d000d)   buffer already wired
# (2d000e)   buffer too large
# (2d000f)   no GPU microcode loaded
# (2d0010)   error reported by draw processor

#           OS / DMA manager
# (2e0001)   illegal channel
# (2e0002)   illegal byte count
# (2e0003)   channel in use
# (2e0004)   channel not allocated for operation
# (2e0005)   operation did not finish

#           OS / IEEE 802.3
# (2f0001)   internal driver error
# (2f0002)   feature is not implemented
# (2f0003)   driver version mismatch
# (2f0004)   device is off-line
# (2f0005)   device is already on-line
# (2f0006)   adapter hardware error
# (2f0007)   transmit operation failed
# (2f0008)   invalid unit number
# (2f0009)   illegal packet length
# (2f000a)   invalid statistics block
# (2f000b)   packet type is already in use
# (2f000c)   no channels are available
# (2f000d)   no packet available for receive
# (2f000e)   invalid packet type
# (2f000f)   channel is not open
# (2f0010)   address is not a multicast
# (2f0011)   multicast list is full
# (2f0012)   address is a multicast
# (2f0013)   packet type is not already in use
# (2f0014)   illegal destination address

#           OS / audit trail manager
# (300001)   invalid data size
# (300002)   file already open
# (300003)   excessive event types
# (300004)   event logging is disabled
# (300005)   this process is not being audited
# (300006)   event type is not being audited
# (300007)   invalid action code
# (300008)   permission to perform action is denied
# (300009)   attempted to perform a redundant action
# (30000a)   could not start event logging
# (30000b)   file not open
# (30000c)   could not find audit event list
# (30000d)   not configured
# (30000e)   event logging already started
# (30000f)   event logging already stopped
# (300010)   event list format is not the current version

#           OS / Ring
# (310001)   feature is not implemented
# (310002)   invalid controller unit number
# (310003)   illegal header length
# (310004)   illegal data length
# (310005)   transmit operation failed
# (310006)   no packet available to receive
# (310007)   packet type is already in use
# (310008)   no channels are available
# (310009)   invalid svc packet type
# (31000a)   channel is not open
# (31000b)   device is off-line
# (31000c)   device is already on-line
# (31000d)   internal driver error
# (31000e)   controller hardware error
# (31000f)   packet type is not already in use
# (310010)   driver version mismatch
# (310011)   invalid statistics block
# (310012)   illegal destination address

#           OS / Areas
# (320001)   no free areas
# (320002)   area in use
# (320003)   cannot grow shared area
# (320004)   illegal area grow request
# (320005)   no free resources
# (320006)   area not active
# (320007)   not owner of area
# (320008)   cannot unmap area
# (320009)   no deactivatable pmaps
# (32000a)   internal error
# (32000b)   bad reserve

#           OS / utility bus manager
# (330001)   undefined interrupt
# (330002)   bus error interrupt
# (330003)   bus timeout
# (330004)   no response from gate array
# (330005)   error during interrupt cycle

#           OS / pc/at bus manager
# (340001)   undefined interrupt
# (340002)   bus error interrupt
# (340003)   pc/at bus-generated ubus error
# (340004)   iomap parity error
# (340005)   iocheck asserted on pc/at bus
# (340006)   pc/at bus refresh timeout

#           OS / terminal handler
# (350001)   invalid option
# (350002)   invalid value for special function character
# (350003)   invalid handle
# (350004)   supplied buffer is too small
# (350005)   end of file
# (350006)   invalid output buffer length
# (350007)   quit while waiting for input
# (350008)   get conditional failed - no data available
# (350009)   input buffer overrun
# (35000a)   put conditional failed - no room for data
# (35000b)   timeout expired

#           OS / serial I/O
# (360001)   invalid option
# (360002)   illegal parameter value
# (360003)   invalid handle
# (360004)   character framing error
# (360005)   character parity error
# (360006)   data carrier detect (dcd) changed
# (360007)   clear to send (cts) changed
# (360008)   incompatible speed request
# (360009)   input buffer overrun
# (36000a)   quit while waiting

#           OS / Ring 802.5
# (370001)   internal driver error
# (370002)   feature is not implemented
# (370003)   driver version mismatch
# (370004)   device is off-line
# (370005)   device is already on-line
# (370006)   adapter hardware error
# (370007)   transmit operation failed
# (370008)   invalid unit number
# (370009)   illegal frame length
# (37000a)   invalid statistics block
# (37000b)   frame type is already in use
# (37000c)   no channels are available
# (37000d)   no frame available for receive
# (37000e)   invalid frame type
# (37000f)   channel is not open
# (370010)   frame type is not already in use
# (370011)   illegal destination address
# (370012)   size of receive buffer less than received frame

#           OS / SCSI manager
# (380001)   SCSI bus not present
# (380002)   bad handle passed in call
# (380003)   device in use
# (380004)   device not acquired
# (380005)   device already acquired
# (380006)   bad parameter
# (380007)   buffer too large
# (380008)   page not wired
# (380009)   page already wired
# (38000a)   too many wired pages
# (38000b)   bad length
# (38000c)   bad buffer address
# (38000d)   unsupported function
# (38000e)   invalid iova
# (38000f)   device already allocated
# (380010)   operation timeout
# (380011)   hardware timeout
# (380012)   hardware failure
# (380013)   internal manager error
# (380014)   quit fault received during wait
# (380015)   all devices in use
# (380016)   illegal bus revision
# (380017)   protection violation
# (380018)   no resources available
# (380019)   command in progress
# (38001a)   DMA overrun
# (38001b)   DMA underrun
# (38001c)   parity error
# (38001d)   illegal command
# (38001e)   illegal data direction
# (38001f)   scsi target disconnected
# (380020)   scsi target not available
# (380021)   no such operation
# (380022)   host selected by another initiator
# (380023)   scsi bus reset detected
# (380024)   host illegally reselected
# (380025)   unknown message sent to host
# (380026)   illegal scsi bus phase
# (380027)   target is not a system device
# (380028)   illegal system device command
# (380029)   system device is busy
# (38002a)   ddf is larger then expected
# (38002b)   ddf has wrong version
# (38002c)   ddf has wrong file type

#           OS / XNS Error Protocol
# (390001)   source is broadcast address
# (390002)   illegal buffer specification
# (390003)   packet type error
# (390004)   cannot open to XNS IDP

#           OS / MAC-independent interface
# (3a0001)   port operation not implemented
# (3a0002)   no channels available
# (3a0003)   packet type table full
# (3a0004)   invalid packet type
# (3a0005)   packet type in use
# (3a0006)   no OS sockets available
# (3a0007)   caller specified neither OS socket nor demux proc
# (3a0008)   channel is not open
# (3a0009)   no socket allocated for caller
# (3a000a)   no packet available to receive
# (3a000b)   data capacity too small for received packet
# (3a000c)   illegal buffer specification
# (3a000d)   invalid port version number
# (3a0010)   could not put packet into socket
# (3a0011)   invalid port number
# (3a0012)   invalid type count
# (3a0013)   illegal destination address

#           OS / XNS IDP
# (3b0001)   no channels available
# (3b0002)   no OS sockets available
# (3b0003)   caller specified neither OS socket nor demux proc
# (3b0004)   channel is not open
# (3b0005)   no socket allocated for caller
# (3b0006)   no packet available to receive
# (3b0007)   data capacity too small for received packet
# (3b0008)   illegal buffer specification
# (3b0009)   address in use
# (3b000a)   invalid type count
# (3b000b)   listen network not connected
# (3b000c)   illegal IDP socket
# (3b000d)   IDP socket table full
# (3b000e)   IDP socket in use
# (3b000f)   OS socket not open
# (3b0010)   no client for packet
# (3b0011)   bad IDP checksum
# (3b0012)   maximum hops exceeded by packet
# (3b0013)   network unreachable
# (3b0014)   illegal OS socket
# (3b0015)   invalid version number
# (3b0016)   could not put packet into socket
# (3b0017)   no OS socket depth given
# (3b0018)   cannot send only as well as listen
# (3b0019)   cannot send only as well as connect
# (3b001a)   cannot connect to broadcast address
# (3b001b)   connection source address must be this node
# (3b001c)   cannot connect as well as listen
# (3b001d)   host address table full

#           OS / Routing Information Protocol
# (3c0001)   network unreachable
# (3c0002)   cannot open to XNS IDP

#           OS / Apollo-private Protocol
# (3d0001)   could not put packet into socket

#           OS / System Bus Manager
# (3e0001)   undefined interrupt
# (3e0002)   unknown interrupt ID

#           OS / Kernel Memory Allocator
# (3f0001)   internal error
# (3f0002)   already allocated
# (3f0003)   already free
# (3f0004)   allocation failure

#           OS / Thread Manager
# (400001)   thread not found
# (400002)   thread termination in progress
# (400003)   bad thread state
# (400004)   thread not suspended
# (400005)   thread interrupted

#           OS / Recovered Disk Error Manager
# (410001)   disk error recovered by device retry
# (410002)   disk error recovered by device crc
# (410003)   disk error recovered by some device action
# (410004)   disk error recovered by some OS action


ok = askYesNo("Warning", "Warning: This will create types/equates. Continue?")
if ok:
    add_types_and_equates()
