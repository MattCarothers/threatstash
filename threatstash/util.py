#####################
# Refang indicators #
#####################
def refang(ioc):
    # Turn www[dot]site[dot]com into www.site.com
    ioc = ioc.replace("[dot]", ".")
    # Turn www(dot)site(dot)com into www.site.com
    ioc = ioc.replace("(dot)", ".")
    # Turn 1.2.3[,]4 into 1.2.3.4
    ioc = ioc.replace("[,]", ".")
    # Turn 1.2.3[.]4 into 1.2.3.4
    ioc = ioc.replace("[.]", ".")
    # Turn bad.guy .com into bad.guy.com
    ioc = ioc.replace(" .", ".")
    # Turn hxxp into http
    ioc = ioc.replace("hxxp", "http")
    return ioc

#####################
# Defang indicators #
#####################
def defang(ioc):
    # Turn www.site.com into www[.]site[.]com
    ioc = ioc.replace(".", "[.]")
    # Turn http into hxxp
    ioc = ioc.replace("http", "hxxp")
    return ioc
