package main

import (
    "log"
    "os"
    "github.com/miekg/dns"
    "strings"
)

type domainCheck struct {
    url string
    ipv4, ipv6, domain, reverseIp      bool
}

var domainChecks []domainCheck

func checkSingleRecord(domain domainCheck, domainToCheck string, ipToCheck string, ipv6ToCheck string, mode string) bool {
    var target string 
    var server string
    var returnState bool
    debug := false
    if(domain.reverseIp) {
        s := strings.Split(ipToCheck, ".")
        for i, j := 0, len(s)-1; i < j; i, j = i+1, j-1 {
            s[i], s[j] = s[j], s[i]
        }
        ipToCheck = strings.Join(s, ".")

        s = strings.Split(ipv6ToCheck, ":")
        for i, j := 0, len(s)-1; i < j; i, j = i+1, j-1 {
            s[i], s[j] = s[j], s[i]
        }
        ipv6ToCheck = strings.Join(s, ":")
    }

    target = ""
    if(mode == "ipv4") {
        target = ipToCheck
    }
    if(mode == "ipv6") {
        target = ipv6ToCheck
    }
    if(mode == "domain") {
        target = domainToCheck
    }
    target = target + "."
    target = target + domain.url
    server = "8.8.8.8"
    returnState = false
    
    if(debug) {
        log.Print("Target: " + target)
    }

    c := dns.Client{}
    m := dns.Msg{}
    m.SetQuestion(target+".", dns.TypeA)
    r, _, err := c.Exchange(&m, server+":53")
    if err != nil {
        log.Print(err.Error() + "; skipping " + target + " because of network problems.")
        return true
    }
    if len(r.Answer) == 0 {
        if(debug) {
            log.Print("No results! Perfect")
        } 
        returnState = true
    }else{
        log.Print("Found something. Checks need to be written. ( " + target + " )")
        // TODO check in detail
        returnState = false
        // TODO finished
        for _, ans := range r.Answer {
            Arecord := ans.(*dns.A)
            log.Printf("%s", Arecord.A)
        }
    }
    if(debug) {
        log.Print("...  Check finished")
    }
    return returnState
}

func main() {

// based on http://multirbl.valli.org/list/
// find: ^(.*?)\t(.*?)\t(.*?)\t(.*?)\t(.*?)\t(.*?)\t(.*?)(.*)$
// replace: domainCheck { url: "$3", ipv4: $4, ipv6: $5, domain: $6,  reverseIp: false},
// cleanup:
// find: ipv[46],
// replace: true,
// find: -,
// replace: false,
// find: dom,
// replace: true,
// Manually removed are only contact checks.
// All reverse entries I know are marked as reversed: true
    domainChecks = []domainCheck{
        domainCheck { url: "0spam.fusionzero.com", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
        domainCheck { url: "0spamtrust.fusionzero.com", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
        domainCheck { url: "0spam-killlist.fusionzero.com", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
        domainCheck { url: "0spamurl.fusionzero.com", ipv4: false, ipv6: false, domain: true,  reverseIp: false},
        domainCheck { url: "uribl.zeustracker.abuse.ch", ipv4: false, ipv6: false, domain: true,  reverseIp: false},
        domainCheck { url: "ipbl.zeustracker.abuse.ch", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
//       domainCheck { url: "contacts.abuse.net", ipv4: false, ipv6: false, domain: true,  reverseIp: false},
        domainCheck { url: "rbl.abuse.ro", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
        domainCheck { url: "uribl.abuse.ro", ipv4: false, ipv6: false, domain: true,  reverseIp: false},
//       domainCheck { url: "abuse-contacts.abusix.org", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
        domainCheck { url: "spam.dnsbl.anonmails.de", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
        domainCheck { url: "list.anonwhois.net", ipv4: false, ipv6: false, domain: true,  reverseIp: false},
        domainCheck { url: "dnsbl.anticaptcha.net", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
        domainCheck { url: "dnsbl6.anticaptcha.net", ipv4: false, ipv6: true, domain: false,  reverseIp: false},
        domainCheck { url: "orvedb.aupads.org", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
        domainCheck { url: "rsbl.aupads.org", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
        domainCheck { url: "block.ascams.com", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
        domainCheck { url: "superblock.ascams.com", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
        domainCheck { url: "aspews.ext.sorbs.net", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
        domainCheck { url: "ips.backscatterer.org", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
        domainCheck { url: "b.barracudacentral.org", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
        domainCheck { url: "bb.barracudacentral.org", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
        domainCheck { url: "list.bbfh.org", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
        domainCheck { url: "l1.bbfh.ext.sorbs.net", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
        domainCheck { url: "l2.bbfh.ext.sorbs.net", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
        domainCheck { url: "l3.bbfh.ext.sorbs.net", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
        domainCheck { url: "l4.bbfh.ext.sorbs.net", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
// Returing Values but not explaining
//        domainCheck { url: "all.ascc.dnsbl.bit.nl", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
//        domainCheck { url: "all.v6.ascc.dnsbl.bit.nl", ipv4: false, ipv6: true, domain: false,  reverseIp: false},
//        domainCheck { url: "all.dnsbl.bit.nl", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
        domainCheck { url: "ipv6.all.dnsbl.bit.nl", ipv4: false, ipv6: true, domain: false,  reverseIp: false},
        domainCheck { url: "bitonly.dnsbl.bit.nl", ipv4: true, ipv6: true, domain: false,  reverseIp: false},
        domainCheck { url: "blacklist.netcore.co.in", ipv4: false, ipv6: false, domain: true,  reverseIp: false},
        domainCheck { url: "rbl.blakjak.net", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
        domainCheck { url: "netscan.rbl.blockedservers.com", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
        domainCheck { url: "rbl.blockedservers.com", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
        domainCheck { url: "spam.rbl.blockedservers.com", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
        domainCheck { url: "list.blogspambl.com", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
        domainCheck { url: "bsb.empty.us", ipv4: true, ipv6: false, domain: true,  reverseIp: false},
        domainCheck { url: "bsb.spamlookup.net", ipv4: true, ipv6: false, domain: true,  reverseIp: false},
        domainCheck { url: "query.bondedsender.org", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
        domainCheck { url: "plus.bondedsender.org", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
// Network dies
//        domainCheck { url: "dnsbl1.dnsbl.borderware.com", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
//        domainCheck { url: "dnsbl2.dnsbl.borderware.com", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
//        domainCheck { url: "dnsbl3.dnsbl.borderware.com", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
//        domainCheck { url: "dul.dnsbl.borderware.com", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
        domainCheck { url: "blacklist.sci.kun.nl", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
        domainCheck { url: "whitelist.sci.kun.nl", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
        domainCheck { url: "dul.blackhole.cantv.net", ipv4: true, ipv6: false, domain: true,  reverseIp: false},
        domainCheck { url: "hog.blackhole.cantv.net", ipv4: true, ipv6: false, domain: true,  reverseIp: false},
        domainCheck { url: "rhsbl.blackhole.cantv.net", ipv4: true, ipv6: false, domain: true,  reverseIp: false},
        domainCheck { url: "rot.blackhole.cantv.net", ipv4: true, ipv6: false, domain: true,  reverseIp: false},
        domainCheck { url: "spam.blackhole.cantv.net", ipv4: true, ipv6: false, domain: true,  reverseIp: false},
        domainCheck { url: "cbl.anti-spam.org.cn", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
        domainCheck { url: "cblplus.anti-spam.org.cn", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
        domainCheck { url: "cblless.anti-spam.org.cn", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
        domainCheck { url: "cdl.anti-spam.org.cn", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
        domainCheck { url: "cml.anti-spam.org.cn", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
        domainCheck { url: "cbl.abuseat.org", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
        domainCheck { url: "rbl.choon.net", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
        domainCheck { url: "rwl.choon.net", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
        domainCheck { url: "ipv6.rbl.choon.net", ipv4: false, ipv6: true, domain: false,  reverseIp: false},
        domainCheck { url: "ipv6.rwl.choon.net", ipv4: false, ipv6: true, domain: false,  reverseIp: false},
// No Blacklist. See: http://countries.nerd.dk/
//        domainCheck { url: "zz.countries.nerd.dk", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
        domainCheck { url: "dnsbl.cyberlogic.net", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
        domainCheck { url: "bogons.cymru.com", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
        domainCheck { url: "v4.fullbogons.cymru.com", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
// No Documentation available
//        domainCheck { url: "v6.fullbogons.cymru.com", ipv4: false, ipv6: true, domain: false,  reverseIp: false},
//        domainCheck { url: "origin.asn.cymru.com", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
//        domainCheck { url: "origin6.asn.cymru.com", ipv4: false, ipv6: true, domain: false,  reverseIp: false},
//        domainCheck { url: "peer.asn.cymru.com", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
        domainCheck { url: "tor.dan.me.uk", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
        domainCheck { url: "torexit.dan.me.uk", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
        domainCheck { url: "ex.dnsbl.org", ipv4: false, ipv6: false, domain: true,  reverseIp: false},
        domainCheck { url: "in.dnsbl.org", ipv4: false, ipv6: false, domain: true,  reverseIp: false},
        domainCheck { url: "rbl.dns-servicios.com", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
        domainCheck { url: "dnsbl.calivent.com.pe", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
        domainCheck { url: "dnsbl.mcu.edu.tw", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
        domainCheck { url: "dnsbl.net.ua", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
        domainCheck { url: "dnsbl.othello.ch", ipv4: false, ipv6: false, domain: true,  reverseIp: false},
        domainCheck { url: "dnsbl.rv-soft.info", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
        domainCheck { url: "dnsblchile.org", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
        domainCheck { url: "dnsrbl.org", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
        domainCheck { url: "list.dnswl.org", ipv4: true, ipv6: true, domain: false,  reverseIp: false},
        domainCheck { url: "vote.drbl.caravan.ru", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
        domainCheck { url: "work.drbl.caravan.ru", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
        domainCheck { url: "vote.drbldf.dsbl.ru", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
        domainCheck { url: "work.drbldf.dsbl.ru", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
        domainCheck { url: "vote.drbl.gremlin.ru", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
        domainCheck { url: "work.drbl.gremlin.ru", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
        domainCheck { url: "bl.drmx.org", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
        domainCheck { url: "dnsbl.dronebl.org", ipv4: true, ipv6: true, domain: false,  reverseIp: false},
        domainCheck { url: "rbl.efnet.org", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
        domainCheck { url: "rbl.efnetrbl.org", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
        domainCheck { url: "tor.efnet.org", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
        domainCheck { url: "bl.emailbasura.org", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
        domainCheck { url: "rbl.fasthosts.co.uk", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
        domainCheck { url: "bl.fmb.la", ipv4: true, ipv6: false, domain: true,  reverseIp: false},
        domainCheck { url: "communicado.fmb.la", ipv4: false, ipv6: false, domain: true,  reverseIp: false},
        domainCheck { url: "nsbl.fmb.la", ipv4: false, ipv6: false, domain: true,  reverseIp: false},
        domainCheck { url: "sa.fmb.la", ipv4: false, ipv6: false, domain: true,  reverseIp: false},
        domainCheck { url: "short.fmb.la", ipv4: false, ipv6: false, domain: true,  reverseIp: false},
        domainCheck { url: "fnrbl.fast.net", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
        domainCheck { url: "forbidden.icm.edu.pl", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
        domainCheck { url: "88.blocklist.zap", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
        domainCheck { url: "hil.habeas.com", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
        domainCheck { url: "accredit.habeas.com", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
        domainCheck { url: "sa-accredit.habeas.com", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
        domainCheck { url: "hul.habeas.com", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
        domainCheck { url: "sohul.habeas.com", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
// Only checks if domain is new or not: http://wiki.junkemailfilter.com/index.php/Spam_DNS_Lists
//        domainCheck { url: "hostkarma.junkemailfilter.com", ipv4: true, ipv6: false, domain: true,  reverseIp: false},
        domainCheck { url: "nobl.junkemailfilter.com", ipv4: true, ipv6: false, domain: true,  reverseIp: false},
        domainCheck { url: "dnsbl.cobion.com", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
        domainCheck { url: "spamrbl.imp.ch", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
        domainCheck { url: "wormrbl.imp.ch", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
        domainCheck { url: "dnsbl.inps.de", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
        domainCheck { url: "dnswl.inps.de", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
        domainCheck { url: "rbl.interserver.net", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
        domainCheck { url: "(hidden)", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
        domainCheck { url: "(hidden)", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
        domainCheck { url: "(hidden)", ipv4: false, ipv6: false, domain: true,  reverseIp: false},
        domainCheck { url: "rbl.iprange.net", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
        domainCheck { url: "iadb.isipp.com", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
        domainCheck { url: "iadb2.isipp.com", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
        domainCheck { url: "iddb.isipp.com", ipv4: false, ipv6: false, domain: true,  reverseIp: false},
        domainCheck { url: "wadb.isipp.com", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
        domainCheck { url: "whitelist.rbl.ispa.at", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
        domainCheck { url: "mail-abuse.blacklist.jippg.org", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
        domainCheck { url: "dnsbl.justspam.org", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
        domainCheck { url: "dnsbl.kempt.net", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
        domainCheck { url: "spamlist.or.kr", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
        domainCheck { url: "bl.konstant.no", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
        domainCheck { url: "admin.bl.kundenserver.de", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
        domainCheck { url: "relays.bl.kundenserver.de", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
        domainCheck { url: "schizo-bl.kundenserver.de", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
        domainCheck { url: "spamblock.kundenserver.de", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
        domainCheck { url: "worms-bl.kundenserver.de", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
        domainCheck { url: "spamguard.leadmon.net", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
        domainCheck { url: "rbl.lugh.ch", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
        domainCheck { url: "dnsbl.madavi.de", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
        domainCheck { url: "blacklist.mailrelay.att.net", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
        domainCheck { url: "bl.mailspike.net", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
        domainCheck { url: "rep.mailspike.net", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
        domainCheck { url: "wl.mailspike.net", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
        domainCheck { url: "z.mailspike.net", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
        domainCheck { url: "bl.mav.com.br", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
// No Documentation
//        domainCheck { url: "cidr.bl.mcafee.com", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
        domainCheck { url: "rbl.megarbl.net", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
        domainCheck { url: "dnsbl.forefront.microsoft.com", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
        domainCheck { url: "bl.mipspace.com", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
        domainCheck { url: "combined.rbl.msrbl.net", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
        domainCheck { url: "images.rbl.msrbl.net", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
        domainCheck { url: "phishing.rbl.msrbl.net", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
        domainCheck { url: "spam.rbl.msrbl.net", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
        domainCheck { url: "virus.rbl.msrbl.net", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
        domainCheck { url: "web.rbl.msrbl.net", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
        domainCheck { url: "(hidden)", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
        domainCheck { url: "relays.nether.net", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
        domainCheck { url: "trusted.nether.net", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
        domainCheck { url: "unsure.nether.net", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
        domainCheck { url: "ix.dnsbl.manitu.net", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
        domainCheck { url: "no-more-funn.moensted.dk", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
        domainCheck { url: "(hidden)", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
        domainCheck { url: "wl.nszones.com", ipv4: true, ipv6: false, domain: false,  reverseIp: true},
        domainCheck { url: "dyn.nszones.com", ipv4: true, ipv6: false, domain: false,  reverseIp: true},
        domainCheck { url: "sbl.nszones.com", ipv4: true, ipv6: false, domain: false,  reverseIp: true},
        domainCheck { url: "bl.nszones.com", ipv4: true, ipv6: false, domain: false,  reverseIp: true},
        domainCheck { url: "ubl.nszones.com", ipv4: false, ipv6: false, domain: true,  reverseIp: true},
        domainCheck { url: "dnsbl.openresolvers.org", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
        domainCheck { url: "blacklist.mail.ops.asp.att.net", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
        domainCheck { url: "blacklist.sequoia.ops.asp.att.net", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
        domainCheck { url: "spam.pedantic.org", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
        domainCheck { url: "pofon.foobar.hu", ipv4: true, ipv6: true, domain: false,  reverseIp: false},
        domainCheck { url: "ispmx.pofon.foobar.hu", ipv4: true, ipv6: true, domain: false,  reverseIp: false},
        domainCheck { url: "uribl.pofon.foobar.hu", ipv4: false, ipv6: false, domain: true,  reverseIp: false},
        domainCheck { url: "(hidden)", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
        domainCheck { url: "(hidden)", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
        domainCheck { url: "safe.dnsbl.prs.proofpoint.com", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
        domainCheck { url: "bad.psky.me", ipv4: true, ipv6: false, domain: false,  reverseIp: true},
        domainCheck { url: "psbl.surriel.com", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
        domainCheck { url: "whitelist.surriel.com", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
        domainCheck { url: "all.rbl.jp", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
        domainCheck { url: "dyndns.rbl.jp", ipv4: false, ipv6: false, domain: true,  reverseIp: false},
        domainCheck { url: "short.rbl.jp", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
        domainCheck { url: "url.rbl.jp", ipv4: false, ipv6: false, domain: true,  reverseIp: false},
        domainCheck { url: "virus.rbl.jp", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
        domainCheck { url: "rbl.rbldns.ru", ipv4: true, ipv6: false, domain: false,  reverseIp: true},
        domainCheck { url: "rbl.schulte.org", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
        domainCheck { url: "rbl.talkactive.net", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
        domainCheck { url: "rbl.zenon.net", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
        domainCheck { url: "access.redhawk.org", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
        domainCheck { url: "eswlrev.dnsbl.rediris.es", ipv4: true, ipv6: true, domain: false,  reverseIp: false},
        domainCheck { url: "mtawlrev.dnsbl.rediris.es", ipv4: true, ipv6: true, domain: false,  reverseIp: false},
        domainCheck { url: "abuse.rfc-clueless.org", ipv4: false, ipv6: false, domain: true,  reverseIp: false},
        domainCheck { url: "bogusmx.rfc-clueless.org", ipv4: false, ipv6: false, domain: true,  reverseIp: false},
        domainCheck { url: "dsn.rfc-clueless.org", ipv4: false, ipv6: false, domain: true,  reverseIp: false},
        domainCheck { url: "elitist.rfc-clueless.org", ipv4: false, ipv6: false, domain: true,  reverseIp: false},
// Removed because it is only an information
//        domainCheck { url: "fulldom.rfc-clueless.org", ipv4: false, ipv6: false, domain: true,  reverseIp: false},
        domainCheck { url: "postmaster.rfc-clueless.org", ipv4: false, ipv6: false, domain: true,  reverseIp: false},
// Removed because it is only an information
//        domainCheck { url: "whois.rfc-clueless.org", ipv4: false, ipv6: false, domain: true,  reverseIp: false},
        domainCheck { url: "dnsbl.rizon.net", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
        domainCheck { url: "dynip.rothen.com", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
        domainCheck { url: "asn.routeviews.org", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
        domainCheck { url: "aspath.routeviews.org", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
        domainCheck { url: "dnsbl.rymsho.ru", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
        domainCheck { url: "rhsbl.rymsho.ru", ipv4: false, ipv6: false, domain: true,  reverseIp: false},
        domainCheck { url: "all.s5h.net", ipv4: true, ipv6: true, domain: false,  reverseIp: false},
        domainCheck { url: "public.sarbl.org", ipv4: false, ipv6: false, domain: true,  reverseIp: false},
        domainCheck { url: "rhsbl.scientificspam.net", ipv4: false, ipv6: false, domain: true,  reverseIp: false},
        domainCheck { url: "bl.scientificspam.net", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
        domainCheck { url: "reputation-domain.rbl.scrolloutf1.com", ipv4: false, ipv6: false, domain: true,  reverseIp: false},
        domainCheck { url: "reputation-ip.rbl.scrolloutf1.com", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
        domainCheck { url: "reputation-ns.rbl.scrolloutf1.com", ipv4: false, ipv6: false, domain: true,  reverseIp: false},
        domainCheck { url: "tor.dnsbl.sectoor.de", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
        domainCheck { url: "exitnodes.tor.dnsbl.sectoor.de", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
        domainCheck { url: "query.senderbase.org", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
        domainCheck { url: "sa.senderbase.org", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
        domainCheck { url: "rf.senderbase.org", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
        domainCheck { url: "bl.score.senderscore.com", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
// Removed because of missing documentation ( and perhaps only is for scoring )
//        domainCheck { url: "score.senderscore.com", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
        domainCheck { url: "singular.ttk.pte.hu", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
        domainCheck { url: "blackholes.scconsult.com", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
// Removed because of missing documentation
//        domainCheck { url: "dnsbl.sorbs.net", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
//        domainCheck { url: "problems.dnsbl.sorbs.net", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
//        domainCheck { url: "proxies.dnsbl.sorbs.net", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
//        domainCheck { url: "relays.dnsbl.sorbs.net", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
//        domainCheck { url: "safe.dnsbl.sorbs.net", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
//        domainCheck { url: "nomail.rhsbl.sorbs.net", ipv4: false, ipv6: false, domain: true,  reverseIp: false},
//        domainCheck { url: "badconf.rhsbl.sorbs.net", ipv4: false, ipv6: false, domain: true,  reverseIp: false},
//        domainCheck { url: "dul.dnsbl.sorbs.net", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
//        domainCheck { url: "zombie.dnsbl.sorbs.net", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
//        domainCheck { url: "block.dnsbl.sorbs.net", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
//        domainCheck { url: "escalations.dnsbl.sorbs.net", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
//        domainCheck { url: "http.dnsbl.sorbs.net", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
//        domainCheck { url: "misc.dnsbl.sorbs.net", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
//        domainCheck { url: "smtp.dnsbl.sorbs.net", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
//        domainCheck { url: "socks.dnsbl.sorbs.net", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
//        domainCheck { url: "rhsbl.sorbs.net", ipv4: false, ipv6: false, domain: true,  reverseIp: false},
//        domainCheck { url: "spam.dnsbl.sorbs.net", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
//        domainCheck { url: "recent.spam.dnsbl.sorbs.net", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
//        domainCheck { url: "new.spam.dnsbl.sorbs.net", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
//        domainCheck { url: "old.spam.dnsbl.sorbs.net", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
//        domainCheck { url: "web.dnsbl.sorbs.net", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
        domainCheck { url: "korea.services.net", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
        domainCheck { url: "geobl.spameatingmonkey.net", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
// Removed because shows only informations ( https://spameatingmonkey.com/services/SEM-ASN-ORIGIN )
//        domainCheck { url: "origin.asn.spameatingmonkey.net", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
        domainCheck { url: "backscatter.spameatingmonkey.net", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
        domainCheck { url: "badnets.spameatingmonkey.net", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
        domainCheck { url: "bl.spameatingmonkey.net", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
        domainCheck { url: "fresh.spameatingmonkey.net", ipv4: false, ipv6: false, domain: true,  reverseIp: false},
        domainCheck { url: "fresh10.spameatingmonkey.net", ipv4: false, ipv6: false, domain: true,  reverseIp: false},
        domainCheck { url: "fresh15.spameatingmonkey.net", ipv4: false, ipv6: false, domain: true,  reverseIp: false},
        domainCheck { url: "bl.ipv6.spameatingmonkey.net", ipv4: false, ipv6: true, domain: false,  reverseIp: false},
        domainCheck { url: "netbl.spameatingmonkey.net", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
        domainCheck { url: "uribl.spameatingmonkey.net", ipv4: false, ipv6: false, domain: true,  reverseIp: false},
        domainCheck { url: "urired.spameatingmonkey.net", ipv4: false, ipv6: false, domain: true,  reverseIp: false},
        domainCheck { url: "netblockbl.spamgrouper.to", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
        domainCheck { url: "all.spam-rbl.fr", ipv4: true, ipv6: false, domain: false,  reverseIp: true},
        domainCheck { url: "bl.spamcannibal.org", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
        domainCheck { url: "bl.spamcop.net", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
        domainCheck { url: "dbl.spamhaus.org", ipv4: false, ipv6: false, domain: true,  reverseIp: false},
        domainCheck { url: "_vouch.dwl.spamhaus.org", ipv4: false, ipv6: false, domain: true,  reverseIp: false},
        domainCheck { url: "pbl.spamhaus.org", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
        domainCheck { url: "sbl.spamhaus.org", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
        domainCheck { url: "sbl-xbl.spamhaus.org", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
        domainCheck { url: "swl.spamhaus.org", ipv4: true, ipv6: true, domain: false,  reverseIp: false},
        domainCheck { url: "xbl.spamhaus.org", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
        domainCheck { url: "zen.spamhaus.org", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
        domainCheck { url: "feb.spamlab.com", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
        domainCheck { url: "rbl.spamlab.com", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
        domainCheck { url: "all.spamrats.com", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
        domainCheck { url: "dyna.spamrats.com", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
        domainCheck { url: "noptr.spamrats.com", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
        domainCheck { url: "spam.spamrats.com", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
        domainCheck { url: "spamsources.fabel.dk", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
        domainCheck { url: "bl.spamstinks.com", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
        domainCheck { url: "dnsbl.spfbl.net", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
        domainCheck { url: "dul.pacifier.net", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
        domainCheck { url: "bl.suomispam.net", ipv4: true, ipv6: true, domain: false,  reverseIp: false},
        domainCheck { url: "dbl.suomispam.net", ipv4: false, ipv6: false, domain: true,  reverseIp: false},
        domainCheck { url: "gl.suomispam.net", ipv4: true, ipv6: true, domain: false,  reverseIp: false},
        domainCheck { url: "multi.surbl.org", ipv4: true, ipv6: false, domain: true,  reverseIp: false},
        domainCheck { url: "srn.surgate.net", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
        domainCheck { url: "dnsrbl.swinog.ch", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
        domainCheck { url: "uribl.swinog.ch", ipv4: false, ipv6: false, domain: true,  reverseIp: false},
        domainCheck { url: "rbl.tdk.net", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
        domainCheck { url: "st.technovision.dk", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
        domainCheck { url: "dob.sibl.support-intelligence.net", ipv4: false, ipv6: false, domain: true,  reverseIp: false},
        domainCheck { url: "dbl.tiopan.com", ipv4: false, ipv6: false, domain: true,  reverseIp: false},
        domainCheck { url: "bl.tiopan.com", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
        domainCheck { url: "dnsbl.tornevall.org", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
        domainCheck { url: "r.mail-abuse.com", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
        domainCheck { url: "q.mail-abuse.com", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
        domainCheck { url: "rbl2.triumf.ca", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
        domainCheck { url: "wbl.triumf.ca", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
        domainCheck { url: "truncate.gbudb.net", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
        domainCheck { url: "dunk.dnsbl.tuxad.de", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
        domainCheck { url: "hartkore.dnsbl.tuxad.de", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
        domainCheck { url: "dnsbl-0.uceprotect.net", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
        domainCheck { url: "dnsbl-1.uceprotect.net", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
        domainCheck { url: "dnsbl-2.uceprotect.net", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
        domainCheck { url: "dnsbl-3.uceprotect.net", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
        domainCheck { url: "ubl.unsubscore.com", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
        domainCheck { url: "black.uribl.com", ipv4: false, ipv6: false, domain: true,  reverseIp: false},
        domainCheck { url: "grey.uribl.com", ipv4: false, ipv6: false, domain: true,  reverseIp: false},
        domainCheck { url: "multi.uribl.com", ipv4: false, ipv6: false, domain: true,  reverseIp: false},
        domainCheck { url: "red.uribl.com", ipv4: false, ipv6: false, domain: true,  reverseIp: false},
        domainCheck { url: "white.uribl.com", ipv4: false, ipv6: false, domain: true,  reverseIp: false},
        domainCheck { url: "free.v4bl.org", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
        domainCheck { url: "ip.v4bl.org", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
        domainCheck { url: "virbl.dnsbl.bit.nl", ipv4: true, ipv6: true, domain: false,  reverseIp: false},
        domainCheck { url: "all.rbl.webiron.net", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
        domainCheck { url: "babl.rbl.webiron.net", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
        domainCheck { url: "cabl.rbl.webiron.net", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
        domainCheck { url: "crawler.rbl.webiron.net", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
        domainCheck { url: "stabl.rbl.webiron.net", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
        domainCheck { url: "ips.whitelisted.org", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
        domainCheck { url: "blacklist.woody.ch", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
        domainCheck { url: "ipv6.blacklist.woody.ch", ipv4: false, ipv6: true, domain: false,  reverseIp: false},
        domainCheck { url: "uri.blacklist.woody.ch", ipv4: false, ipv6: false, domain: true,  reverseIp: false},
        domainCheck { url: "db.wpbl.info", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
        domainCheck { url: "bl.blocklist.de", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
        domainCheck { url: "dnsbl.zapbl.net", ipv4: true, ipv6: false, domain: false,  reverseIp: false},
        domainCheck { url: "rhsbl.zapbl.net", ipv4: false, ipv6: false, domain: true,  reverseIp: false},
    }


    ipToCheck := os.Args[1]
    domainToCheck := ""
    if(len(os.Args) > 2) {
        domainToCheck = os.Args[2]
    }
    ipv6ToCheck := ""
    if(len(os.Args) > 3) {
        ipv6ToCheck = os.Args[3]
    }

    if(ipToCheck == "") {
        log.Fatal("No IP to check. please call script with at least 1 argument. './server 127.0.0.1 mailDomain.tld ::1'")
    }

    returnValue := 0

    for _,domain := range domainChecks {
        if(domain.ipv4 && ipToCheck != "") {
            if(!checkSingleRecord(domain, domainToCheck, ipToCheck, ipv6ToCheck, "ipv4")) {
                returnValue = 1
            }
        }
        if(domain.ipv6 && ipv6ToCheck != "") {
            if(!checkSingleRecord(domain, domainToCheck, ipToCheck, ipv6ToCheck, "ipv6")) {
                returnValue = 1
            }
        }
        if(domain.domain && domainToCheck != "") {
            if(!checkSingleRecord(domain, domainToCheck, ipToCheck, ipv6ToCheck, "domain")) {
                returnValue = 1
            }
        }
    }

    os.Exit(returnValue)
}