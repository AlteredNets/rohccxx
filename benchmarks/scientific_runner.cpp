extern "C" {
#include <rohc/rohc_comp.h>
#include <rohc/rohc_decomp.h>
}
#include <dlfcn.h>
#include <sys/utsname.h>
#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include <memory>
#include <map>
#include <regex>
#include <sstream>
#include <string>
#include <vector>

#undef rohc_buf_init_full
#undef rohc_buf_init_empty
static rohc_buf full_buf(uint8_t *p,size_t n,rohc_ts t){rohc_buf b{};b.time=t;b.data=p;b.max_len=n;b.len=n;return b;}
static rohc_buf empty_buf(uint8_t *p,size_t n){rohc_buf b{};b.data=p;b.max_len=n;return b;}

namespace {
constexpr uint64_t Seed=0x524f484343585832ULL;
constexpr size_t Capacity=2048, CorpusPackets=65536, Establish=3, MinOps=1000000;
constexpr double MinSeconds=4.0;
enum class Profile{RTP,UDP,ESP,IP}; enum class Impl{XX,LIB,CONTROL}; enum class Op{COMP,DECOMP,ROUND,CONTROL};
struct Packet{std::vector<uint8_t> b;uint32_t flow=0,ordinal=0;};
struct Encoded{std::array<uint8_t,Capacity> b{};size_t n=0;};
struct Result{uint64_t ns=0,ops=0,in=0,out=0,guards=0,incorrect=0;};
static std::string root;
static bool TimingEnabled=true;
static uint64_t ClockEntries=0;
static std::string slurp(const std::string&p){std::ifstream f(p,std::ios::binary);if(!f)throw std::runtime_error("open "+p);return {std::istreambuf_iterator<char>(f),{}};}
static std::string cmd(const std::string&c){std::array<char,512>b{};std::string s;FILE*p=popen(c.c_str(),"r");if(!p)throw std::runtime_error("popen");while(fgets(b.data(),b.size(),p))s+=b.data();if(pclose(p)!=0)throw std::runtime_error("command failed");while(!s.empty()&&(s.back()=='\n'||s.back()=='\r'))s.pop_back();return s;}
static std::string q(const std::string&s){std::string r="'";for(char c:s){if(c=='\'')r+="'\\''";else r+=c;}return r+="'";}
static std::string hash(const std::string&p){auto s=cmd("sha256sum "+q(p));return s.substr(0,s.find(' '));}
static void require(bool x,const std::string&m){if(!x)throw std::runtime_error(m);}
static const char* pn(Profile p){return p==Profile::RTP?"rtp_udp_ipv4":p==Profile::UDP?"udp_ipv4":p==Profile::ESP?"esp_ipv4":"ip_only_ipv4";}
static const char* in(Impl i){return i==Impl::XX?"rohccxx":i==Impl::LIB?"rohclib":"control";}
static const char* on(Op o){return o==Op::COMP?"steady_compress":o==Op::DECOMP?"steady_decompress":o==Op::ROUND?"round_trip":"control";}
static void p16(uint8_t*p,uint16_t v){p[0]=v>>8;p[1]=v;} static void p32(uint8_t*p,uint32_t v){p[0]=v>>24;p[1]=v>>16;p[2]=v>>8;p[3]=v;}
static uint16_t csum(const uint8_t*p,size_t n){uint32_t s=0;for(size_t i=0;i<n;i+=2){s+=uint16_t(p[i])<<8;if(i+1<n)s+=p[i+1];}while(s>>16)s=(s&65535)+(s>>16);return uint16_t(~s);}
static Packet make(Profile x,size_t payload,uint32_t flow,uint32_t ord){size_t h=x==Profile::RTP?40:(x==Profile::IP?20:28);Packet z;z.flow=flow;z.ordinal=ord;z.b.assign(h+payload,0);auto*p=z.b.data();p[0]=0x45;p16(p+2,z.b.size());p16(p+4,uint16_t(0x1234u+flow));p16(p+6,0x4000);p[8]=64;p[9]=(x==Profile::RTP||x==Profile::UDP)?17:x==Profile::ESP?50:253;p[12]=10;p[14]=flow;p[15]=1;p[16]=10;p[18]=flow;p[19]=2;if(x==Profile::RTP||x==Profile::UDP){p16(p+20,10000+flow);p16(p+22,20000+flow);p16(p+24,z.b.size()-20);}if(x==Profile::RTP){p[28]=0x80;p[29]=96;p16(p+30,uint16_t(1000+ord));p32(p+32,160000+ord*160);p32(p+36,0x11223300+flow);}if(x==Profile::ESP){p32(p+20,0x10203000+flow);p32(p+24,ord);}uint64_t s=Seed^(uint64_t(flow)<<32)^ord;for(size_t j=h;j<z.b.size();j++){s^=s<<13;s^=s>>7;s^=s<<17;p[j]=uint8_t(s);}if(x==Profile::UDP&&payload)p[h]&=0x3f;p16(p+10,csum(p,20));return z;}
static std::vector<Packet> corpus(Profile p,size_t payload,uint32_t flows,bool setup){std::vector<Packet>v;size_t n=setup?size_t(flows)*Establish:CorpusPackets;v.reserve(n);if(setup){for(uint32_t f=0;f<flows;f++)for(uint32_t o=0;o<Establish;o++)v.push_back(make(p,payload,f,o));}else for(size_t i=0;i<n;i++){uint32_t f=i%flows,o=Establish+i/flows;v.push_back(make(p,payload,f,o));}return v;}
struct XX{using New=void*(*)(uint32_t,int);using Free=void(*)(void*);using Set=int(*)(void*,uint32_t);using Code=int(*)(void*,const uint8_t*,size_t,uint8_t*,size_t*);void*h{};New nc{},nd{};Free fc{},fd{};Set set{};Code comp{},dec{};XX(){h=dlopen((root+"/build-release/src/librohccxx.so.0.4.1").c_str(),RTLD_NOW|RTLD_LOCAL);require(h,"dlopen rohccxx");nc=(New)dlsym(h,"rohc_comp_new2");nd=(New)dlsym(h,"rohc_decomp_new2");fc=(Free)dlsym(h,"rohc_comp_free");fd=(Free)dlsym(h,"rohc_decomp_free");set=(Set)dlsym(h,"rohc_comp_set_cid");comp=(Code)dlsym(h,"rohc_compress4");dec=(Code)dlsym(h,"rohc_decompress4");require(nc&&nd&&fc&&fd&&set&&comp&&dec,"rohccxx symbols");}~XX(){if(h)dlclose(h);}};
static int rnd(const rohc_comp*,void*){return 0x5a;} static bool rtp(const unsigned char*,const unsigned char*,const unsigned char*p,unsigned int n,void*){return n>=12&&(p[0]>>6)==2;}
struct LC{void operator()(rohc_comp*p)const{rohc_comp_free(p);}};struct LD{void operator()(rohc_decomp*p)const{rohc_decomp_free(p);}};
using LCP=std::unique_ptr<rohc_comp,LC>;using LDP=std::unique_ptr<rohc_decomp,LD>;
static rohc_profile_t pid(Profile p){return static_cast<rohc_profile_t>(p==Profile::RTP?ROHC_PROFILE_RTP:p==Profile::UDP?ROHC_PROFILE_UDP:p==Profile::ESP?ROHC_PROFILE_ESP:ROHC_PROFILE_IP);}
static LCP lc(Profile p){LCP c(rohc_comp_new2(ROHC_SMALL_CID,15,rnd,nullptr));require(bool(c),"lib comp");require(rohc_comp_enable_profile(c.get(),pid(p)),"lib profile");if(p==Profile::RTP)require(rohc_comp_set_rtp_detection_cb(c.get(),rtp,nullptr),"rtp cb");return c;}
static LDP ld(Profile p){LDP d(rohc_decomp_new2(ROHC_SMALL_CID,15,ROHC_U_MODE));require(bool(d),"lib decomp");require(rohc_decomp_enable_profile(d.get(),pid(p)),"lib profile");return d;}
static bool lcomp(rohc_comp*c,const Packet&p,uint8_t*out,size_t&n){rohc_ts t{p.ordinal,0};auto ib=full_buf(const_cast<uint8_t*>(p.b.data()),p.b.size(),t);auto ob=empty_buf(out,n);bool ok=rohc_compress4(c,ib,&ob)==ROHC_STATUS_OK;n=ob.len;return ok;}
static bool ldec(rohc_decomp*d,const Encoded&e,uint8_t*out,size_t&n,uint32_t ord){rohc_ts t{ord,0};auto ib=full_buf(const_cast<uint8_t*>(e.b.data()),e.n,t);auto ob=empty_buf(out,n);bool ok=rohc_decompress3(d,ib,&ob,nullptr,nullptr)==ROHC_STATUS_OK;n=ob.len;return ok;}
static std::vector<Encoded> encode(Impl impl,Profile p,const std::vector<Packet>&setup,const std::vector<Packet>&v,std::vector<Encoded>*es){XX x;std::vector<Encoded>out;out.reserve(v.size());if(es)es->clear();if(impl==Impl::XX){void*c=x.nc(15,0);require(c,"xx comp");auto one=[&](const Packet&a){Encoded e;e.n=Capacity;require(x.set(c,a.flow)==0&&x.comp(c,a.b.data(),a.b.size(),e.b.data(),&e.n)==0,"xx preencode");return e;};for(auto&a:setup)if(es)es->push_back(one(a));else(void)one(a);for(auto&a:v)out.push_back(one(a));x.fc(c);}else{auto c=lc(p);for(auto&a:setup){Encoded e;e.n=Capacity;require(lcomp(c.get(),a,e.b.data(),e.n),"lib preencode");if(es)es->push_back(e);}for(auto&a:v){Encoded e;e.n=Capacity;require(lcomp(c.get(),a,e.b.data(),e.n),"lib preencode");out.push_back(e);}}return out;}
template<class F> static uint64_t timed(F&&f){if(!TimingEnabled){f();return 0;}ClockEntries++;auto a=std::chrono::steady_clock::now();f();auto b=std::chrono::steady_clock::now();return std::chrono::duration_cast<std::chrono::nanoseconds>(b-a).count();}
static Result batch_clean(Impl impl,Op op,Profile p,const std::vector<Packet>&setup,const std::vector<Packet>&v,const std::vector<Encoded>&es,const std::vector<Encoded>&ev,size_t reps){
 Result r;std::array<uint8_t,Capacity+2>o{},c{};uint64_t input_per_rep=0;for(const auto&a:v)input_per_rep+=a.b.size();XX x;
 for(size_t rep=0;rep<reps;rep++){
  o.front()=0xa5;o.back()=0x5a;c.front()=0x3c;c.back()=0xc3;bool ok=true;uint64_t output=0;
  if(impl==Impl::CONTROL){r.ns+=timed([&]{for(const auto&a:v)memcpy(o.data()+1,a.b.data(),a.b.size());});output=input_per_rep;}
  else if(impl==Impl::XX){
   void*co=x.nc(15,0),*de=x.nd(15,0);require(co&&de,"xx context");
   for(size_t j=0;j<setup.size();j++){size_t cn=Capacity,on=Capacity;require(x.set(co,setup[j].flow)==0&&x.comp(co,setup[j].b.data(),setup[j].b.size(),c.data()+1,&cn)==0,"xx setup comp");const uint8_t*sp=op==Op::DECOMP?es[j].b.data():c.data()+1;size_t sn=op==Op::DECOMP?es[j].n:cn;require(x.dec(de,sp,sn,o.data()+1,&on)==0,"xx setup dec");}
   r.ns+=timed([&]{for(size_t j=0;j<v.size();j++){size_t cn=Capacity,on=Capacity;if(op==Op::COMP){ok=ok&&x.set(co,v[j].flow)==0&&x.comp(co,v[j].b.data(),v[j].b.size(),c.data()+1,&cn)==0;output+=cn;}else if(op==Op::DECOMP){ok=ok&&x.dec(de,ev[j].b.data(),ev[j].n,o.data()+1,&on)==0;output+=on;}else{ok=ok&&x.set(co,v[j].flow)==0&&x.comp(co,v[j].b.data(),v[j].b.size(),c.data()+1,&cn)==0&&x.dec(de,c.data()+1,cn,o.data()+1,&on)==0;output+=on;}}});x.fc(co);x.fd(de);
  }else{
   auto co=lc(p);auto de=ld(p);
   for(size_t j=0;j<setup.size();j++){Encoded e{};e.n=Capacity;require(lcomp(co.get(),setup[j],e.b.data(),e.n),"lib setup comp");size_t on=Capacity;require(ldec(de.get(),op==Op::DECOMP?es[j]:e,o.data()+1,on,setup[j].ordinal),"lib setup dec");}
   r.ns+=timed([&]{for(size_t j=0;j<v.size();j++){size_t cn=Capacity,on=Capacity;if(op==Op::COMP){ok=ok&&lcomp(co.get(),v[j],c.data()+1,cn);output+=cn;}else if(op==Op::DECOMP){ok=ok&&ldec(de.get(),ev[j],o.data()+1,on,v[j].ordinal);output+=on;}else{Encoded e{};ok=ok&&lcomp(co.get(),v[j],e.b.data(),e.n)&&ldec(de.get(),e,o.data()+1,on,v[j].ordinal);output+=on;}}});
  }
  r.ops+=v.size();r.in+=input_per_rep;r.out+=output;if(!ok)r.incorrect++;if(o.front()!=0xa5||o.back()!=0x5a||c.front()!=0x3c||c.back()!=0xc3)r.guards++;
 }
 return r;
}
static void validate_manifest(const std::string&m){auto s=slurp(m);for(auto*x:{"\"release\": \"0.4.1\"","\"seed_hex\": \"0x524f484343585832\"","\"packets_per_workload\": 65536","\"warmup_operations_per_treatment\": 10000","\"minimum_measured_operations\": 1000000","\"minimum_measured_seconds\": 4.0","\"iterations\": 21","not a cross-version comparison","v0.4.0 excluded"})require(s.find(x)!=std::string::npos,std::string("manifest: ")+x);require(s.find("[0, 20, 160, 1200]")!=std::string::npos,"payloads");require(s.find("[1, 4, 16]")!=std::string::npos,"flows");}
static void identity(const char*self,const std::string&m){validate_manifest(m);require(cmd("uname -m")=="x86_64","arch");require(slurp("/etc/os-release").find("VERSION_ID=\"24.04\"")!=std::string::npos,"os");require(cmd("/usr/bin/g++-13 -dumpfullversion")=="13.3.0","compiler");auto resolved=slurp(root+"/harness-build/experiment-resolved-v0.4.1.txt");for(auto p:{m,std::string(self),root+"/harness-src/scientific_runner.cpp",root+"/harness-build/effective-flags.txt",root+"/incoming/rohccxx-0.4.1-source-with-submodules.tar.gz",root+"/build-release/src/librohccxx.so.0.4.1",root+"/rohclib-build-normalized/src/.libs/librohc.so.3.0.0"})require(resolved.find(hash(p)+"  "+p)!=std::string::npos,"identity "+p);}
static bool verify_case(Profile p,size_t payload,uint32_t flows){auto fail=[&](Impl i,const char*phase,size_t j,size_t actual,size_t expected){std::cerr<<"VERIFY_FAIL,"<<pn(p)<<','<<payload<<','<<flows<<','<<in(i)<<','<<phase<<','<<j<<",actual="<<actual<<",expected="<<expected<<'\n';return false;};auto s=corpus(p,payload,flows,true),v=corpus(p,payload,flows,false);for(Impl i:{Impl::XX,Impl::LIB}){std::vector<Encoded>es;auto ev=encode(i,p,s,v,&es);std::array<uint8_t,Capacity+2>o{};if(i==Impl::XX){XX x;void*d=x.nd(15,0);if(!d)return false;for(size_t j=0;j<s.size();j++){o.front()=0xa5;o.back()=0x5a;size_t n=Capacity;if(x.dec(d,es[j].b.data(),es[j].n,o.data()+1,&n)!=0||n!=s[j].b.size()||memcmp(o.data()+1,s[j].b.data(),n)||o.front()!=0xa5||o.back()!=0x5a){x.fd(d);return fail(i,"setup",j,n,s[j].b.size());}}for(size_t j=0;j<v.size();j++){o.front()=0xa5;o.back()=0x5a;size_t n=Capacity;if(x.dec(d,ev[j].b.data(),ev[j].n,o.data()+1,&n)!=0||n!=v[j].b.size()||memcmp(o.data()+1,v[j].b.data(),n)||o.front()!=0xa5||o.back()!=0x5a){x.fd(d);return fail(i,"steady",j,n,v[j].b.size());}}x.fd(d);}else{auto d=ld(p);for(size_t j=0;j<s.size();j++){o.front()=0xa5;o.back()=0x5a;size_t n=Capacity;if(!ldec(d.get(),es[j],o.data()+1,n,s[j].ordinal)||n!=s[j].b.size()||memcmp(o.data()+1,s[j].b.data(),n)||o.front()!=0xa5||o.back()!=0x5a)return fail(i,"setup",j,n,s[j].b.size());}for(size_t j=0;j<v.size();j++){o.front()=0xa5;o.back()=0x5a;size_t n=Capacity;if(!ldec(d.get(),ev[j],o.data()+1,n,v[j].ordinal)||n!=v[j].b.size()||memcmp(o.data()+1,v[j].b.data(),n)||o.front()!=0xa5||o.back()!=0x5a)return fail(i,"steady",j,n,v[j].b.size());}}}auto r=batch_clean(Impl::CONTROL,Op::CONTROL,p,s,v,{}, {},1);return !r.guards&&!r.incorrect;}
static void csv(const std::string&path,Profile p,size_t payload,uint32_t flows,Impl i,Op o,int iteration,const Result&r,const char*label){std::ofstream f(path,std::ios::app);require(bool(f),"csv");f<<"1,0.4.1,"<<pn(p)<<','<<payload<<','<<flows<<','<<in(i)<<','<<on(o)<<','<<iteration<<','<<r.ops<<','<<r.ns<<','<<r.in<<','<<r.out<<','<<r.guards<<','<<r.incorrect<<','<<label<<'\n';}
static Result warmup(Impl i,Op o,Profile p,const std::vector<Packet>&s,const std::vector<Packet>&v,const std::vector<Encoded>&es,const std::vector<Encoded>&ev){require(v.size()>=10000,"warmup corpus");std::vector<Packet>w(v.begin(),v.begin()+10000);std::vector<Encoded>we;if(o==Op::DECOMP)we.assign(ev.begin(),ev.begin()+10000);uint64_t before=ClockEntries;TimingEnabled=false;auto r=batch_clean(i,o,p,s,w,es,we,1);TimingEnabled=true;require(r.ops==10000,"warmup exact count");require(r.ns==0&&ClockEntries==before,"warmup entered timer");require(!r.guards&&!r.incorrect,"warmup correctness");return r;}
static std::string key(Profile p,size_t z,uint32_t f,Impl i,Op o){return std::string(pn(p))+","+std::to_string(z)+","+std::to_string(f)+","+in(i)+","+on(o);}
static std::map<std::string,size_t> read_plan(const std::string&path){std::ifstream f(path);require(bool(f),"calibration plan missing");std::map<std::string,size_t>m;std::string line;while(std::getline(f,line)){if(line.empty()||line.rfind("profile,",0)==0)continue;auto pos=line.rfind(',');require(pos!=std::string::npos,"calibration plan syntax");size_t reps=std::stoull(line.substr(pos+1));require(reps>0,"calibration plan reps");require(m.emplace(line.substr(0,pos),reps).second,"duplicate calibration plan key");}return m;}
static void header(const std::string&path){std::ofstream h(path);require(bool(h),"raw output");h<<"schema,release,profile,payload,flows,implementation,operation,iteration,operations,elapsed_ns,input_bytes,output_bytes,guards,incorrect,gate_status\n";}
static std::vector<std::pair<Impl,Op>> tasks(){return {{Impl::XX,Op::COMP},{Impl::LIB,Op::COMP},{Impl::XX,Op::DECOMP},{Impl::LIB,Op::DECOMP},{Impl::XX,Op::ROUND},{Impl::LIB,Op::ROUND},{Impl::CONTROL,Op::CONTROL}};}
}

int main(int argc,char**argv)
{
 try {
  std::string mode,manifest,runroot; bool authorize_final=false,self_test=false; size_t shard=0,shards=1;
  for(int a=1;a<argc;a++) { std::string x=argv[a];
   if(x=="--mode"&&a+1<argc) mode=argv[++a]; else if(x=="--manifest"&&a+1<argc) manifest=argv[++a];
   else if(x=="--root"&&a+1<argc) runroot=argv[++a]; else if(x=="--authorize-final") authorize_final=true;
   else if(x=="--self-test") self_test=true; else if(x=="--shard"&&a+2<argc){shard=std::stoull(argv[++a]);shards=std::stoull(argv[++a]);} else throw std::runtime_error("arguments"); }
  require(mode=="correctness"||mode=="calibration"||mode=="final","--mode");
  require(!manifest.empty()&&!runroot.empty(),"manifest/root required");
  if(mode=="final") require(authorize_final,"final requires --authorize-final"); else require(!authorize_final,"authorization valid only for final");
  root=runroot; identity(argv[0],manifest);
  std::vector<Profile> profiles{Profile::RTP,Profile::UDP,Profile::ESP,Profile::IP};
  std::vector<size_t> payloads{0,20,160,1200}; std::vector<uint32_t> flow_counts{1,4,16};
  if(self_test) {
   auto s=corpus(Profile::UDP,20,1,true),v=corpus(Profile::UDP,20,1,false); std::vector<Encoded> es,ev;
   uint64_t clocks=ClockEntries; auto w=warmup(Impl::CONTROL,Op::CONTROL,Profile::UDP,s,v,es,ev);
   require(w.ops==10000&&w.ns==0&&ClockEntries==clocks,"warmup self-test");
   auto source=slurp(root+"/harness-src/scientific_runner.cpp");
   require(source.find("TimingEnabled=false;auto r=batch_clean")!=std::string::npos,"warmup source boundary");
   require(source.find("CALIBRATION_NON_REPORTABLE")!=std::string::npos,"calibration source label");
   std::cout<<"SELF_TEST,warmup_exact_10000,PASS\nSELF_TEST,warmup_timer_entries_0,PASS\nSELF_TEST,calibration_non_reportable,PASS\nSELF_TEST,timing_boundary_source_contract,PASS\n"; return 0;
  }
  if(mode=="correctness") { for(auto p:profiles)for(auto z:payloads)for(auto f:flow_counts){require(verify_case(p,z,f),"correctness");std::cout<<"RUNNER_CORRECTNESS,"<<pn(p)<<','<<z<<','<<f<<",PASS\n";} return 0; }
  require(shards>0&&shard<shards,"shard range");const std::string suffix="-shard-"+std::to_string(shard);const std::string calibration=root+"/calibration/raw-calibration-v0.4.1"+suffix+".csv",plan_path=root+"/calibration/calibration-plan-v0.4.1"+suffix+".csv",final_path=root+"/final/raw-final-v0.4.1"+suffix+".csv";
  std::map<std::string,size_t> plan;
  if(mode=="calibration") { header(calibration); std::ofstream pf(plan_path);require(bool(pf),"calibration plan");pf<<"profile,payload,flows,implementation,operation,repetitions\n"; }
  else { plan=read_plan(plan_path);require(slurp(root+"/harness-build/experiment-resolved-v0.4.1.txt").find(hash(plan_path)+"  "+plan_path)!=std::string::npos,"calibration plan identity");header(final_path); }
  size_t case_index=0;
  for(auto p:profiles)for(auto z:payloads)for(auto f:flow_counts){if(case_index%shards!=shard){case_index++;continue;}
   const size_t rotation=case_index++;require(verify_case(p,z,f),"pre validation");auto setup=corpus(p,z,f,true),packets=corpus(p,z,f,false);
   if(mode=="calibration"){auto order=tasks();std::rotate(order.begin(),order.begin()+(rotation%order.size()),order.end());for(auto [impl,op]:order){std::vector<Encoded> encoded_setup,encoded;if(op==Op::DECOMP)encoded=encode(impl,p,setup,packets,&encoded_setup);warmup(impl,op,p,setup,packets,encoded_setup,encoded);auto probe=batch_clean(impl,op,p,setup,packets,encoded_setup,encoded,1);require(probe.ops==CorpusPackets&&probe.ns>0&&!probe.guards&&!probe.incorrect,"discarded probe");size_t by_ops=(MinOps+probe.ops-1)/probe.ops,by_time=size_t((MinSeconds*1e9+probe.ns-1)/probe.ns),reps=std::max<size_t>(1,std::max(by_ops,by_time));auto measured=batch_clean(impl,op,p,setup,packets,encoded_setup,encoded,reps);require(measured.ops>=MinOps&&measured.ns>=uint64_t(MinSeconds*1e9)&&!measured.guards&&!measured.incorrect,"calibration gate");csv(calibration,p,z,f,impl,op,-1,measured,"CALIBRATION_NON_REPORTABLE");std::ofstream pf(plan_path,std::ios::app);require(bool(pf),"plan append");pf<<key(p,z,f,impl,op)<<','<<reps<<'\n';}}
   else for(int iteration=0;iteration<21;iteration++){auto order=tasks();std::rotate(order.begin(),order.begin()+((rotation+iteration)%order.size()),order.end());for(auto [impl,op]:order){std::vector<Encoded> encoded_setup,encoded;if(op==Op::DECOMP)encoded=encode(impl,p,setup,packets,&encoded_setup);auto it=plan.find(key(p,z,f,impl,op));require(it!=plan.end(),"calibration plan case");warmup(impl,op,p,setup,packets,encoded_setup,encoded);auto measured=batch_clean(impl,op,p,setup,packets,encoded_setup,encoded,it->second);require(measured.ops>=MinOps&&measured.ns>0&&!measured.guards&&!measured.incorrect,"final gate");csv(final_path,p,z,f,impl,op,iteration,measured,"FINAL_VALID");}}
   require(verify_case(p,z,f),"post validation");
  }return 0;
 }catch(const std::exception&e){std::cerr<<"REFUSED,"<<e.what()<<'\n';return 2;}
}
