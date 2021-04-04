global relationship:table[addr] of set[string]={};
event user_agent(c:connection)
{
  local s:addr=c$id$orig_h;
  if(c$http?$user_agent)
  {
	local agent:string=to_lower(c$http$user_agent);
	if (s in relationship)
	{
    	if(agent !in relationship[s])
    		add relationship[s][agent];
	 }
	else
	{
    	local myset:set[string]={agent};
    	relationship[s]=myset;
	}
  }
  
}
event zeek_done()
{
  for(source_ip in relationship)
  {
    if(|relationship[source_ip]|>=3)
      print fmt("%s is a proxy",source_ip);
  }
}
