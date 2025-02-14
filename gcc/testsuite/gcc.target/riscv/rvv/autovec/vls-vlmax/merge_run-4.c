/* { dg-do run { target { riscv_vector } } } */
/* { dg-options "-O3 --param riscv-autovec-preference=fixed-vlmax" } */

#include "merge-4.c"

int main(void)
{
    vnx128qi vnx128qi_x= {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,\
                          16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,\
                          32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,\
                          48,49,50,51,52,53,54,55,56,57,58,59,60,61,62,63,\
                          64,65,66,67,68,69,70,71,72,73,74,75,76,77,78,79,\
                          80,81,82,83,84,85,86,87,88,89,90,91,92,93,94,95,\
                          96,97,98,99,100,101,102,103,104,105,106,107,108,109,110,111,\
                          112,113,114,115,116,117,118,119,120,121,122,123,124,125,126,127
                         };
    vnx128qi vnx128qi_y= {128,129,130,131,132,133,134,135,136,137,138,139,140,141,142,143,\
                          144,145,146,147,148,149,150,151,152,153,154,155,156,157,158,159,\
                          160,161,162,163,164,165,166,167,168,169,170,171,172,173,174,175,\
                          176,177,178,179,180,181,182,183,184,185,186,187,188,189,190,191,\
                          192,193,194,195,196,197,198,199,200,201,202,203,204,205,206,207,\
                          208,209,210,211,212,213,214,215,216,217,218,219,220,221,222,223,\
                          224,225,226,227,228,229,230,231,232,233,234,235,236,237,238,239,\
                          240,241,242,243,244,245,246,247,248,249,250,251,252,253,254,255
                         };
    vnx128qi vnx128qi_expect= {0,129,2,131,4,133,6,135,8,137,10,139,12,141,14,143,\
                               16,145,18,147,20,149,22,151,24,153,26,155,28,157,30,159,\
                               32,161,34,163,36,165,38,167,40,169,42,171,44,173,46,175,\
                               48,177,50,179,52,181,54,183,56,185,58,187,60,189,62,191,\
                               64,193,66,195,68,197,70,199,72,201,74,203,76,205,78,207,\
                               80,209,82,211,84,213,86,215,88,217,90,219,92,221,94,223,\
                               96,225,98,227,100,229,102,231,104,233,106,235,108,237,110,239,\
                               112,241,114,243,116,245,118,247,120,249,122,251,124,253,126,255
                              };
    vnx128qi vnx128qi_real;
    merge0(vnx128qi_x,vnx128qi_y,&vnx128qi_real);
    for(int i=0; i<128; i++)
        if(vnx128qi_real[i]!=vnx128qi_expect[i]) {
            __builtin_abort();
        }

    vnx128uqi vnx128uqi_x= {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,\
                            16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,\
                            32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,\
                            48,49,50,51,52,53,54,55,56,57,58,59,60,61,62,63,\
                            64,65,66,67,68,69,70,71,72,73,74,75,76,77,78,79,\
                            80,81,82,83,84,85,86,87,88,89,90,91,92,93,94,95,\
                            96,97,98,99,100,101,102,103,104,105,106,107,108,109,110,111,\
                            112,113,114,115,116,117,118,119,120,121,122,123,124,125,126,127
                           };
    vnx128uqi vnx128uqi_y= {128,129,130,131,132,133,134,135,136,137,138,139,140,141,142,143,\
                            144,145,146,147,148,149,150,151,152,153,154,155,156,157,158,159,\
                            160,161,162,163,164,165,166,167,168,169,170,171,172,173,174,175,\
                            176,177,178,179,180,181,182,183,184,185,186,187,188,189,190,191,\
                            192,193,194,195,196,197,198,199,200,201,202,203,204,205,206,207,\
                            208,209,210,211,212,213,214,215,216,217,218,219,220,221,222,223,\
                            224,225,226,227,228,229,230,231,232,233,234,235,236,237,238,239,\
                            240,241,242,243,244,245,246,247,248,249,250,251,252,253,254,255
                           };
    vnx128uqi vnx128uqi_expect= {0,129,2,131,4,133,6,135,8,137,10,139,12,141,14,143,\
                                 16,145,18,147,20,149,22,151,24,153,26,155,28,157,30,159,\
                                 32,161,34,163,36,165,38,167,40,169,42,171,44,173,46,175,\
                                 48,177,50,179,52,181,54,183,56,185,58,187,60,189,62,191,\
                                 64,193,66,195,68,197,70,199,72,201,74,203,76,205,78,207,\
                                 80,209,82,211,84,213,86,215,88,217,90,219,92,221,94,223,\
                                 96,225,98,227,100,229,102,231,104,233,106,235,108,237,110,239,\
                                 112,241,114,243,116,245,118,247,120,249,122,251,124,253,126,255
                                };
    vnx128uqi vnx128uqi_real;
    merge1(vnx128uqi_x,vnx128uqi_y,&vnx128uqi_real);
    for(int i=0; i<128; i++)
        if(vnx128uqi_real[i]!=vnx128uqi_expect[i]) {
            __builtin_abort();
        }

    vnx64hi vnx64hi_x= {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,\
                        17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,\
                        33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,\
                        49,50,51,52,53,54,55,56,57,58,59,60,61,62,63,64
                       };
    vnx64hi vnx64hi_y= {101,102,103,104,105,106,107,108,109,110,111,112,113,114,115,116,\
                        117,118,119,120,121,122,123,124,125,126,127,128,129,130,131,132,\
                        133,134,135,136,137,138,139,140,141,142,143,144,145,146,147,148,\
                        149,150,151,152,153,154,155,156,157,158,159,160,161,162,163,164
                       };
    vnx64hi vnx64hi_expect= {1,102,3,104,5,106,7,108,9,110,11,112,13,114,15,116,\
                             17,118,19,120,21,122,23,124,25,126,27,128,29,130,31,132,\
                             33,134,35,136,37,138,39,140,41,142,43,144,45,146,47,148,\
                             49,150,51,152,53,154,55,156,57,158,59,160,61,162,63,164,
                            };
    vnx64hi vnx64hi_real;
    merge2(vnx64hi_x,vnx64hi_y,&vnx64hi_real);
    for(int i=0; i<64; i++)
        if(vnx64hi_real[i]!=vnx64hi_expect[i]) {
            __builtin_abort();
        }

    vnx64uhi vnx64uhi_x= {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,\
                          17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,\
                          33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,\
                          49,50,51,52,53,54,55,56,57,58,59,60,61,62,63,64
                         };
    vnx64uhi vnx64uhi_y= {101,102,103,104,105,106,107,108,109,110,111,112,113,114,115,116,\
                          117,118,119,120,121,122,123,124,125,126,127,128,129,130,131,132,\
                          133,134,135,136,137,138,139,140,141,142,143,144,145,146,147,148,\
                          149,150,151,152,153,154,155,156,157,158,159,160,161,162,163,164
                         };
    vnx64uhi vnx64uhi_expect= {1,102,3,104,5,106,7,108,9,110,11,112,13,114,15,116,\
                               17,118,19,120,21,122,23,124,25,126,27,128,29,130,31,132,\
                               33,134,35,136,37,138,39,140,41,142,43,144,45,146,47,148,\
                               49,150,51,152,53,154,55,156,57,158,59,160,61,162,63,164,
                              };
    vnx64uhi vnx64uhi_real;
    merge3(vnx64uhi_x,vnx64uhi_y,&vnx64uhi_real);
    for(int i=0; i<64; i++)
        if(vnx64uhi_real[i]!=vnx64uhi_expect[i]) {
            __builtin_abort();
        }

    vnx32si vnx32si_x= {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32};
    vnx32si vnx32si_y= {101,102,103,104,105,106,107,108,109,110,111,112,113,114,115,116,117,118,119,120,121,122,123,124,125,126,127,128,129,130,131,132};
    vnx32si vnx32si_expect= {1,102,3,104,5,106,7,108,9,110,11,112,13,114,15,116,17,118,19,120,21,122,23,124,25,126,27,128,29,130,31,132};
    vnx32si vnx32si_real;
    merge4(vnx32si_x,vnx32si_y,&vnx32si_real);
    for(int i=0; i<32; i++)
        if(vnx32si_real[i]!=vnx32si_expect[i]) {
            __builtin_abort();
        }

    vnx32usi vnx32usi_x= {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32};
    vnx32usi vnx32usi_y= {101,102,103,104,105,106,107,108,109,110,111,112,113,114,115,116,117,118,119,120,121,122,123,124,125,126,127,128,129,130,131,132};
    vnx32usi vnx32usi_expect= {1,102,3,104,5,106,7,108,9,110,11,112,13,114,15,116,17,118,19,120,21,122,23,124,25,126,27,128,29,130,31,132};
    vnx32usi vnx32usi_real;
    merge5(vnx32usi_x,vnx32usi_y,&vnx32usi_real);
    for(int i=0; i<32; i++)
        if(vnx32usi_real[i]!=vnx32usi_expect[i]) {
            __builtin_abort();
        }


    vnx16di vnx16di_x= {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
    vnx16di vnx16di_y= {101,102,103,104,105,106,107,108,109,110,111,112,113,114,115,116};
    vnx16di vnx16di_expect= {1,102,3,104,5,106,7,108,9,110,11,112,13,114,15,116};
    vnx16di vnx16di_real;
    merge6(vnx16di_x,vnx16di_y,&vnx16di_real);
    for(int i=0; i<16; i++)
        if(vnx16di_real[i]!=vnx16di_expect[i]) {
            __builtin_abort();
        }

    vnx16udi vnx16udi_x= {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
    vnx16udi vnx16udi_y= {101,102,103,104,105,106,107,108,109,110,111,112,113,114,115,116};
    vnx16udi vnx16udi_expect= {1,102,3,104,5,106,7,108,9,110,11,112,13,114,15,116};
    vnx16udi vnx16udi_real;
    merge7(vnx16udi_x,vnx16udi_y,&vnx16udi_real);
    for(int i=0; i<16; i++)
        if(vnx16udi_real[i]!=vnx16udi_expect[i]) {
            __builtin_abort();
        }

    vnx64hf vnx64hf_x= {1.0,2.0,3.0,4.0,5.0,6.0,7.0,8.0,9.0,10.0,11.0,12.0,13.0,14.0,15.0,16.0,\
                        17.0,18.0,19.0,20.0,21.0,22.0,23.0,24.0,25.0,26.0,27.0,28.0,29.0,30.0,31.0,32.0,\
                        33.0,34.0,35.0,36.0,37.0,38.0,39.0,40.0,41.0,42.0,43.0,44.0,45.0,46.0,47.0,48.0,\
                        49.0,50.0,51.0,52.0,53.0,54.0,55.0,56.0,57.0,58.0,59.0,60.0,61.0,62.0,63.0,64.0
                       };
    vnx64hf vnx64hf_y= {1.1,2.1,3.1,4.1,5.1,6.1,7.1,8.1,9.1,10.1,11.1,12.1,13.1,14.1,15.1,16.1,\
                        17.1,18.1,19.1,20.1,21.1,22.1,23.1,24.1,25.1,26.1,27.1,28.1,29.1,30.1,31.1,32.1,\
                        33.1,34.1,35.1,36.1,37.1,38.1,39.1,40.1,41.1,42.1,43.1,44.1,45.1,46.1,47.1,48.1,\
                        49.1,50.1,51.1,52.1,53.1,54.1,55.1,56.1,57.1,58.1,59.1,60.1,61.1,62.1,63.1,64.1
                       };
    vnx64hf vnx64hf_expect= {1.0,2.1,3.0,4.1,5.0,6.1,7.0,8.1,9.0,10.1,11.0,12.1,13.0,14.1,15.0,16.1,\
                             17.0,18.1,19.0,20.1,21.0,22.1,23.0,24.1,25.0,26.1,27.0,28.1,29.0,30.1,31.0,32.1,\
                             33.0,34.1,35.0,36.1,37.0,38.1,39.0,40.1,41.0,42.1,43.0,44.1,45.0,46.1,47.0,48.1,\
                             49.0,50.1,51.0,52.1,53.0,54.1,55.0,56.1,57.0,58.1,59.0,60.1,61.0,62.1,63.0,64.1
                            };
    vnx64hf vnx64hf_real;
    merge8(vnx64hf_x,vnx64hf_y,&vnx64hf_real);
    for(int i=0; i<64; i++)
        if(vnx64hf_real[i]!=vnx64hf_expect[i]) {
            __builtin_abort();
        }

    vnx32sf vnx32sf_x= {1.0,2.0,3.0,4.0,5.0,6.0,7.0,8.0,9.0,10.0,11.0,12.0,13.0,14.0,15.0,16.0,\
                        17.0,18.0,19.0,20.0,21.0,22.0,23.0,24.0,25.0,26.0,27.0,28.0,29.0,30.0,31.0,32.0
                       };
    vnx32sf vnx32sf_y= {1.1,2.1,3.1,4.1,5.1,6.1,7.1,8.1,9.1,10.1,11.1,12.1,13.1,14.1,15.1,16.1,\
                        17.1,18.1,19.1,20.1,21.1,22.1,23.1,24.1,25.1,26.1,27.1,28.1,29.1,30.1,31.1,32.1
                       };
    vnx32sf vnx32sf_expect= {1.0,2.1,3.0,4.1,5.0,6.1,7.0,8.1,9.0,10.1,11.0,12.1,13.0,14.1,15.0,16.1,\
                             17.0,18.1,19.0,20.1,21.0,22.1,23.0,24.1,25.0,26.1,27.0,28.1,29.0,30.1,31.0,32.1
                            };
    vnx32sf vnx32sf_real;
    merge9(vnx32sf_x,vnx32sf_y,&vnx32sf_real);
    for(int i=0; i<32; i++)
        if(vnx32sf_real[i]!=vnx32sf_expect[i]) {
            __builtin_abort();
        }

    vnx16df vnx16df_x= {1.0,2.0,3.0,4.0,5.0,6.0,7.0,8.0,9.0,10.0,11.0,12.0,13.0,14.0,15.0,16.0};
    vnx16df vnx16df_y= {1.1,2.1,3.1,4.1,5.1,6.1,7.1,8.1,9.1,10.1,11.1,12.1,13.1,14.1,15.1,16.1};
    vnx16df vnx16df_expect= {1.0,2.1,3.0,4.1,5.0,6.1,7.0,8.1,9.0,10.1,11.0,12.1,13.0,14.1,15.0,16.1};
    vnx16df vnx16df_real;
    merge10(vnx16df_x,vnx16df_y,&vnx16df_real);
    for(int i=0; i<16; i++)
        if(vnx16df_real[i]!=vnx16df_expect[i]) {
            __builtin_abort();
        }

    return 0;
}
