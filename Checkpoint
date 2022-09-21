#### Checkpoint

########################
to define new interfaces:
Add the physical interfaces to the firewall -> go to web GUI of that firewall -> go to Network interfaces 
In the network interfaces you will see all the network interfaces that are installed on that firewall. Edit as you like.

To add static route:
Web GUI -> Network Management -> IPv4 Static Routes -> add the routes as you like

to get the configured interfaces on SmartConsole:
Open SmartConsole -> in the Gateways and servers section, click on the firewall -> Network Management -> Click on get interface (with tepology)

########################
to add new GUI Client (a user who can access the firewall through the SmartConsole)
Web GUI of that firewall -> User Management -> Users -> Add 
You can also remove all users, so that no one can access the firewall through the SmartConsole.

to create new admins and manage them:
SmartConsole -> Manage & Settings section
Here you can manage almost everything about the admin and giving them permissions. Go through all the options in this section.

########################
to configure some basic policies:
SmartConsole -> Security Policies -> Policy 

to add/delete/etc new policy:
click right on one of the No. column

to add new Services & application:
click on plus sign on that column and add what you want. 
Also on the right side you can add some services in more detailed. New -> More -> Services 

########################
to enable NAT (Hide/Static)
- Explained in the slides

########################
Note: One Policy called "standard" is installed by default
to create new policy:
SmartConsole -> Security Policy -> click on plus sign tab -> manage policies and layers
here you can create a new policy, name it and set it to a specific target/firewall

to see the implied rules/policies:
SmartConsole -> Security Policy -> Policy -> Actions -> Implied Rules (in the configuration, you can edit the rules)

########################
to edit the global properties:
SmartConsole -> above menu -> global properties

########################
Layer Security: 1.Ordered layers 2.Numbered/inline Layers
to add a new layer:
SmartConsole -> Security Policy -> Click right in the Policy -> edit policy -> click right on the plus sign (access control) -> new layer
Note: You can share this layer with many targets, so any changes in the layer, will be applied on those targets

########################
Recommended Design for Policies:
create 7 Rules and keep the order like it is:
1. VPN Rules (Site-to-Site | Client-to-Site):
2. FW Adminstration:
3. Stealth Rule:
For dropping traffics, that belong
4. Web-Browse & Email:
5. DMZ Access Rules:
6. Network Access Rules (as per requirements):
7. Cleanup Rule:
Any Traffics that does not match any of the above rules, must be dropped.

to go to specific version of your firewall setting, or if something does not work anymore.
SmartConsole -> in the bottom the access tools -> installation history
here you can install any privious version of firewall setting you have used before.

#########################
to enable cluster (see slides)
- Explained in the slides

#########################
logs
two types of logs: 
1.network traffic logs (.log) - normal network logs 
2.audit logs (.adtlog) - logs of the admins and the management servers

for more details see the slides


