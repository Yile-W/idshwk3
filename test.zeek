global relationship:table[addr] of set[string]=table();
event http_header(c: connection, is_orig: bool, name: string, value: string)
{
  local sip:addr=c$id$orig_h;
  if(c$http?$user_agent)
  {
	local agent:string=to_lower(c$http$user_agent);
	if (sip in relationship)
	{
    	if(agent !in relationship[sip])
    		add relationship[sip][agent];
	 }
	else
	{
    		relationship[sip]=set(agent);
	}
  }
  
}
event zeek_done()
{
  for(sip in relationship)
  {
    if(|relationship[sip]|>=3)
      print fmt("%s is a proxy",sip);
  }
}
