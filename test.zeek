global relationship:table[addr] of set[string]={};
event user_agent(c:connection)
{
  local s=c$id$orig_h;
  if (s in relationship[addr])
  {
    if(!(c$id$user_agent in relationship[s]))
      add relationship[s][c$id$user_agent];
  }
  else
  {
    local myset:set[string]={c$id$orig_h};
    relationship[s]=myset;
  }
}
event zeek_done()
{
  for(IP in relationship)
  {
    if(|relationship[IP]|>=3)
      print("%s is a proxy",IP);
  }
}
