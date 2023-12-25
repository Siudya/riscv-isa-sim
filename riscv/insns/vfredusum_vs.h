// vfredsum: vd[0] =  sum( vs2[*] , vs1[0] )
//RTL implement vfredusum.vs as vfredosum.vs instruction.
#ifndef IMPLENMENT_USUM_AS_OSUM
bool is_propagate = true;
#else
bool is_propagate = false;
#endif
VI_VFP_VV_LOOP_REDUCTION
({
  vd_0 = f16_add(vd_0, vs2);
},
{
  vd_0 = f32_add(vd_0, vs2);
},
{
  vd_0 = f64_add(vd_0, vs2);
})
