#include <linux/types.h>
#include <linux/limits.h>

struct bpf_reg_state {
    u32 ref_obj_id;
    s32 s32_min_value; /* minimum possible (s32)value */
    s32 s32_max_value; /* maximum possible (s32)value */
    u32 u32_min_value; /* minimum possible (u32)value */
    u32 u32_max_value; /* maximum possible (u32)value */
    s64 smin_value; /* minimum possible (s64)value */
    s64 smax_value; /* maximum possible (s64)value */
    u64 umin_value; /* minimum possible (u64)value */
    u64 umax_value; /* maximum possible (u64)value */
};

void __mark_reg32_unbounded(struct bpf_reg_state *reg)
{
    reg->s32_min_value = S32_MIN;
    reg->s32_max_value = S32_MAX;
    reg->u32_min_value = 0;
    reg->u32_max_value = U32_MAX;
}

bool __reg64_bound_s32(s64 a)
{
    return a > S32_MIN && a < S32_MAX;
}

bool __reg64_bound_u32(u64 a)
{
    return a > U32_MIN && a < U32_MAX;
}

/* declarations */

extern void __reg_deduce_bounds(struct bpf_reg_state *reg);

extern void __reg32_deduce_bounds(struct bpf_reg_state *reg);

extern void __reg64_deduce_bounds(struct bpf_reg_state *reg);

extern void __reg_bound_offset(struct bpf_reg_state *reg);

extern void __update_reg_bounds(struct bpf_reg_state *reg);

extern void __update_reg32_bounds(struct bpf_reg_state *reg);

extern void __update_reg64_bounds(struct bpf_reg_state *reg);


#include "ebpf_bug.c"
#include "ebpf_fix.c"
