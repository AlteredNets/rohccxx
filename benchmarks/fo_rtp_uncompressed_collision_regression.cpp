#include <rohccxx.h>
#include <rohccxx/core/packet_type.hpp>
#include <array>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <memory>
#include <vector>
namespace {
uint16_t sum(const uint8_t*p,size_t n){uint32_t s=0;for(size_t i=0;i<n;i+=2){s+=uint16_t(p[i])<<8;if(i+1<n)s+=p[i+1];}while(s>>16)s=(s&65535)+(s>>16);return uint16_t(~s);}
void p16(uint8_t*p,uint16_t v){p[0]=v>>8;p[1]=v;} void p32(uint8_t*p,uint32_t v){p[0]=v>>24;p[1]=v>>16;p[2]=v>>8;p[3]=v;}
struct C{void operator()(rohc_comp*p)const{rohc_comp_free(p);}};struct D{void operator()(rohc_decomp*p)const{rohc_decomp_free(p);}};
}
int main(){
 constexpr size_t index=0; std::array<uint8_t,1205> collision{};
 collision[0]=0;collision[1]=0x61;collision[2]=0xc8;collision[3]=0;collision[4]=0xd0;collision[5]=4;collision[6]=0x8c;
 rohccxx::ParsedRohcPacket parsed{};
 if(!rohccxx::parse_rohc_packet(collision.data(),collision.size(),parsed,false)||parsed.type!=rohccxx::RohcPacketType::Uncompressed){std::cerr<<"collision index="<<index<<" classification failure\n";return 1;}
 std::vector<uint8_t> ip(40+collision.size());auto*p=ip.data();p[0]=0x45;p16(p+2,ip.size());p16(p+4,0x4242);p16(p+6,0x4000);p[8]=64;p[9]=17;p[12]=10;p[15]=1;p[16]=10;p[19]=2;p16(p+20,10000);p16(p+22,20000);p16(p+24,20+collision.size());p[28]=0x80;p[29]=96;p16(p+30,1000);p32(p+32,160000);p32(p+36,0x11223344);std::memcpy(p+40,collision.data(),collision.size());p16(p+10,sum(p,20));
 std::unique_ptr<rohc_comp,C>c(rohc_comp_new2(0,ROHCCXX_DIRECTION_UPLINK));std::unique_ptr<rohc_decomp,D>d(rohc_decomp_new2(0,ROHCCXX_DIRECTION_UPLINK));if(!c||!d)return 2;
 std::array<uint8_t,4098>z{},o{};z.front()=0xa5;z.back()=0x5a;size_t zn=4096;if(rohc_compress4(c.get(),ip.data(),ip.size(),z.data()+1,&zn)||z.front()!=0xa5||z.back()!=0x5a)return 3;
 rohccxx::ParsedRohcPacket enc{};if(!rohccxx::parse_rohc_packet(z.data()+1,zn,enc,false))return 4;
 o.front()=0x3c;o.back()=0xc3;size_t on=4096;if(rohc_decompress4(d.get(),z.data()+1,zn,o.data()+1,&on)||o.front()!=0x3c||o.back()!=0xc3||on!=ip.size()||std::memcmp(o.data()+1,ip.data(),on))return 5;
 std::cout<<"COLLISION,PASS,index=0;input_class=Uncompressed;encoded_type="<<unsigned(enc.type)<<";incorrect=0;guards=0\n";
}
