/* This function contains a bug */

void __reg_combine_64_into_32_BUG(struct bpf_reg_state *reg)
{
    __mark_reg32_unbounded(reg);

    if (__reg64_bound_s32(reg->smin_value) && __reg64_bound_s32(reg->smax_value)) {
        reg->s32_min_value = (s32)reg->smin_value;
        reg->s32_max_value = (s32)reg->smax_value;
    }
    if (__reg64_bound_u32(reg->umin_value))
        reg->u32_min_value = (u32)reg->umin_value;
    if (__reg64_bound_u32(reg->umax_value))
        reg->u32_max_value = (u32)reg->umax_value;

    /* Intersecting with the old var_off might have improved our bounds
     * slightly.  e.g. if umax was 0x7f...f and var_off was (0; 0xf...fc),
     * then new var_off is (0; 0x7f...fc) which improves our umax.
     */
    __reg_deduce_bounds(reg);
    __reg_bound_offset(reg);
    __update_reg_bounds(reg);
}

