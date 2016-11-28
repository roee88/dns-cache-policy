# dns-cache-policy

Attacks against DNS impose a serious security threat to today's Internet. Cache poisoning attacks on DNS are one type of attacks that is considered highly dangerous and is being actively investigated by the research community, leading to improvements in the security aspect of popular DNS software applications. In a DNS cache poisoning attack the attacker attempts to override cached records in a resolver application with fake information that allows him e.g. to take control over a domain. Considering different resolver software applications implement caching differently and that security patches have been applied in recent years to make such attacks on the DNS cache less feasible, the method an attacker would use to override cached records varies depending on the DNS software used. In this work we investigate the caching policies of widely used resolver applications to suggest attack methods against them and ultimately provide a tool that would output the best attack payload for any given remotely accessible DNS resolver server. 

Full details [here](https://github.com/roee88/dns-cache-policy/blob/master/ProjectBook.pdf).

Resolvers list omitted from repo due to security considerations.

&copy; Copyright Roee Shlomo 2014-2015
