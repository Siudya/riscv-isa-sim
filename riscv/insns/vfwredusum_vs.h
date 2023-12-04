// vfwredsum.vs vd, vs2, vs1
//RTL implement vfwredusum.vs as vfwredosum.vs instruction.
#ifndef MPLENMENT_USUM_AS_OSUM
bool is_propagate = true;
#else
bool is_propagate = false;
#endif
VI_VFP_VV_LOOP_WIDE_REDUCTION
({
  vd_0 = f32_add(vd_0, vs2);
},
{
  vd_0 = f64_add(vd_0, vs2);
})
