---
layout: writeup
category: ping-CTF-2023
chall_description: N/A
points: 50
solves: 206
tags: rev obfuscation
date: 2023-12-11
comments: false
---

In the last programming session, Bajtek unleashed a coding catastrophe – his spaghetti code was so messy that even the compiler threw up its hands in surrender. Colleagues attempted to debug it, but the code was like a Rubik's Cube on a caffeine overdose. Bajtek proudly declared it an avant-garde programming masterpiece, leaving his coworkers wondering if they should call a programmer's version of an exorcist. In the end, they renamed his file "spaghetti.cpp" to "noodleNightmare.cpp" as a memorial to the chaotic session.  

[58df855a70e2573ee69865930774973a.zip](https://github.com/Nightxade/ctf-writeups/assets/CTFs/ping-CTF-2023/58df855a70e2573ee69865930774973a.zip)  

---

Check out `noodleNightmare.cpp`. Seems like we're given a ton of include statements in order. Maybe we can parse this in Python?  

Copying the entire program, I used [this site](http://www.unit-conversion.info/texttools/replace-text/) to add commas and nice formatting to the program to create an array. Then, I used Python to print nicely formatted output of the program. Here's the Python program I used to format:  

```py
a = ["spaghetti/tjzqohinnyywacrdplxojvooeckayonrdmaycbqcvvxbkibbvv.cpp" ,"spaghetti/pypqtzzchhewyfazdybbzhhkyonlnnpuwsxvydmbukjmdxyxfs.cpp" ,"spaghetti/xwyqezbcclhfyrrruglguuonewdbimuzajxwwospbsybsxwily.cpp" ";" ,"spaghetti/ikghukiounwtmfdscnlbnlfsyoyaymeukjucbishgfsshamuho.cpp" ,"spaghetti/ksplifqbplipxkaitfhhnskiopcbrkecqjgtnoweshaeauujue.cpp" ,"spaghetti/qwohdckkemgarswmeodemdwgkzwypkwxvjffcjcturidajmbnk.cpp" ,"spaghetti/pzoipbuttxofvxezfiphcjnszofrgzwjgjnaomogetsoxsarhy.cpp" ,"spaghetti/hmnqzhbykgeulqjjhthltwxemxfkvttsdlouoflgypsoyuplyi.cpp" ,"spaghetti/ewfecatxwlwbtybolyypjotvxhznrrktapbtooefkexcmzdfyx.cpp" ,"spaghetti/spzsrlbfognxydflsudbnazfsluuilnzrwxbqckugyhthoukxw.cpp" ,"spaghetti/fguyfqgwheqnziwylsnarvtwlmkdaiqvdaphtzczdxdzwrmhpf.cpp" ,"spaghetti/qdcfgiblfknuuycjgpdfqvwsjiwcnhoczfzgudfxanlipmlnva.cpp" ,"spaghetti/ntkmoewbljpqkxwinzdeehytacxnrnecahvvvmeiorwhsnfjlp.cpp" ,"spaghetti/uclwfdyxvvpquxfrauojmvprpxkgfyemubqmipzztemlnxxvsp.cpp" ,"spaghetti/crmubmyrzwxkzozrpzsfnrrqsgxyvwcuapragivcdpndsocrbb.cpp" ";" ,"spaghetti/iqazihugczshgnmrwqleuvleefixwpgiizfouotunehwoybluy.cpp" ,"spaghetti/soyuejoqyurpqejhaupxqoaktmdtyqzxihfmxtsrunagrmdmjo.cpp" ";" ,"spaghetti/bjzfoagpimyhoysgnvmkaxchaprhkqneeghgftkgeyyovcjcig.cpp" ,"spaghetti/hmsbacsmwrlsqqigtyococnwrpioujxjcomrgoybwdxlpgbokx.cpp" ,"spaghetti/cfzpdvcdtokibprvouueypprlzhplrockoxnhyybybuhyshmtt.cpp" ";" ,"spaghetti/rpyottujqrgppymotvqrwdsnqiwmoasgfshvuomzygrsqscayl.cpp" ,"spaghetti/wmigbymrqkfmfzacszezqatqasxbglnjrkvzxdwrxypnjxbloh.cpp" ,"spaghetti/uzazhqwthshesnfqymlbshltjfvcbpbmnomujxptaokcncdszu.cpp" ,"spaghetti/wqkkrlnyxjyxtdbvgijhbooigfrscnxjuafxbeupyyasafsjdh.cpp" ,"spaghetti/pgafltxftijintybmaxnwtvypanhopguztyjfcytdloscdevsw.cpp" ,"spaghetti/zkqmrqcxiobxthzwjfgfuivekqmyehzvlipgynrwukybmbxunt.cpp" ,"spaghetti/ihnoxlticbgojvlplxstykmakfxfxxscvtvcqbpcyngyhbpcjj.cpp" ,"spaghetti/bsaegvddkukumjdajeqrfeuuuhylmzgqgaochtaqklfaztryqc.cpp" ,"spaghetti/syoyvufuvokgzaujjsqavzuesagegimyhcjtkjolsguzvwltfy.cpp" ,"spaghetti/ohtljaxhkrchlcyvxuaofmtmhoxygjohuztffknbojvwpsujob.cpp" ";" ,"spaghetti/hpmjptbshrqagxotpvpfmoeietnaynmctmizvvglxpwsbulxoo.cpp" ,"spaghetti/btsokcahliezsixkcmtzggerkpalfizmriuyeatuzlvpkpuyfv.cpp" ,"spaghetti/pkejtratvrxyxjmqfbpvbwjcylrswlboqoablwlmfskvboxhgj.cpp" ";" ,"spaghetti/nzurqvrgjxypsmqlzturhlmkuujydgkewzodgligiutblxtrmj.cpp" ,"spaghetti/hveqtijkubweqvqmggdncxvswtvglwptobtjdcdqwgokkgwkxj.cpp" ,"spaghetti/hmspqhvxudrzaqrsjdgeegfwwrppvyxickphxjzkbbgccjgaid.cpp" ,"spaghetti/neubacybwyhbyecusdcrcsdomzcgwwbydwyvtrsrmhpxrmhfkp.cpp" ,"spaghetti/fmwfjnhpoitiigpbedxqvfixdaqivxamtuaifleuqkqkwtxsfw.cpp" ,"spaghetti/hjfnebcdxlnzmiynlhinjwvqsbfvorcuudzgffvknljzjlchjr.cpp" ,"spaghetti/axpggcaaqgqicxhxtscvagumyxlgtxusnsvukdbvmtugcqcwcf.cpp" ,"spaghetti/kqxiuprercmgmjmjcareibittmjdxhqoodkdgvnijjkkyzvyln.cpp" ,"spaghetti/jzlezmnuloladbumtyposzexmdtillhlnrerchaplfmpfqltfh.cpp" ,"spaghetti/ccmqhkwtsunsausxybgoaxssypkhmqogvesziruxrakjthmlwp.cpp" ,"spaghetti/repnzejizoqlpsfmlrwlakrrmuhwetvdxbyitniqswlspceueo.cpp" ,"spaghetti/etdclkdtwblujonakelnyzvuzjwdxrtsqgdchbwrqtvreeywhy.cpp" ,"spaghetti/cxjftwjmrzkvbljrvfvstaosmnoinolhjjupfxtcqwndlwsdow.cpp" ";" ,"spaghetti/kgvcqvswbomrrvgayosgonevjcsptqkvrjnlxtqcoxiillsefj.cpp" ,"spaghetti/kfrjpfakjawzfdlefzxeyslcalyiumutzdmmuvraqhewyuskyn.cpp" ,"spaghetti/vgoltirohwlcuejmkhnvkoopjbjpockujpvtwmuzgfobmfboqp.cpp" ,"spaghetti/ykmpqeliraifkcvjpivlcgzehmxzetaggwzptzaglqpfmbocoq.cpp" ,"spaghetti/btopckeyzlcosdgihyodzmirestvkfmxzhefjkcwzdhiboprjp.cpp" ,"spaghetti/izgrpoafquaqswvvlbjkmvilttjvrkzobtgdfwdiszenemawsc.cpp" ,"spaghetti/uthowupivjewtdjlligstbirfsmdyifeiynzwxvsjzdaeymphs.cpp" ";" ,"spaghetti/vnjeyanjgjbmbetgaowaaambztbshnnkxgrqdccluankznaoym.cpp" ,"spaghetti/xhurgrflsfnkccqayornnltbcveifeelngvscskinjelcblcuh.cpp" ,"spaghetti/oynqsgkdccicvxotztmrzstrlxnukgwclnudpgdimdduvprbyx.cpp" ,"spaghetti/zdgvpeuonlzvykvlhpwgsjesgeplgajjhbapwzladdhkpnufoa.cpp" ,"spaghetti/alldppndgicuqwdqbbbklmiclkzpcleoptydsnklbyquiqwaly.cpp" ,"spaghetti/fdmcizqjuofplccgbavkigiumutxiryjwgvrwvcoyywohcpgjb.cpp" ,"spaghetti/ftsiafeqeynzweicdckvjmeuqlsqjfynhbabkfzkrgkjesmelu.cpp" ";" ,"spaghetti/uurxlwpmjrxhoagaabtvgcyjqgjfqoslttlrbvukhmrezanjbi.cpp" ,"spaghetti/tmwehhschjxaobuwpivtmktsifcttgajfjoqvzqnwaitqbgxoc.cpp" ,"spaghetti/tvfpdoziysulibvtkncovvlrlwwdhptqffuwdjbctsceixjcjf.cpp" ,"spaghetti/eirnmftchtljjyewngxsrbkgdjzjxvhcavmfprrhiljsnonpms.cpp" ,"spaghetti/csytxxppykilsevxjarvojlwfwvkconbixdnmaqoryomwtiopn.cpp" ,"spaghetti/uflkirswmlxkmhmfvojbjsdszrniunahmwuxtasfcfnfjecyoe.cpp" ,"spaghetti/fvvcpyukfekvjmwnumbhroikkhbqestqumbhvlfngmchyeahpo.cpp" ";" ,"spaghetti/hddmfmylhkciumgzbuyugavhdpfyobywlzbzajbzgfdktrnadk.cpp" ,"spaghetti/eheukmdasryspfqadbbocwmdmabemqcfioifezdtbbwdxwyyzi.cpp" ,"spaghetti/wpgnlparnbfzavtwedkgklmxwvguaruotfbeoegwbrdwvrnbgf.cpp" ,"spaghetti/pimlbhlodwgefbhgxntzjcfexiumnpgiwkdhjgejlrkoakjhpp.cpp" ,"spaghetti/moqeopqthkxldydlonftmhjnfbxhvfnmsxgbmlzaxdbycmwayo.cpp" ,"spaghetti/fpkylumikhthawaraaeyibbufmqvershzorufvkftuzyhnwtex.cpp" ,"spaghetti/tqwfbpujhydrrpbtocstjshsmktrbsuhnovkzvfayylqtqmlmf.cpp" ";" ,"spaghetti/mnoefxtfsspfmodlvenznyxhibwirrqctlysoxtreweloaumhk.cpp" ,"spaghetti/iutgcjczmuetwdspgadmtqthfabdfniynilamagekrgljzgntn.cpp" ,"spaghetti/yskddnqxpdfcgrrkqsfrdmhrvtopbcohlwebdxcbhyahdhhlfg.cpp" ,"spaghetti/hlvzgmocsekbceburtxobmytxxxnqxxkvbkprrqzcfgukovqiq.cpp" ,"spaghetti/kxqtsoysubfqtslxrnxneebptfwdwrzlysbpotlgkertrucdtz.cpp" ,"spaghetti/nnpaeoycppjvdxteickqilgfsqzpjgtpsyzyvfqwhclzpjzzfn.cpp" ,"spaghetti/sraosqevpafonmctwukgxzqevduclwunpgtnbzsceysxzrsyix.cpp" ";" ,"spaghetti/mwthfslvjhtnewopgvuzlzuqyktvuclezlmdvfldlntuuknxud.cpp" ,"spaghetti/raxkgflwnkhdfkocvqyigljpbwhwmibgdbsfsagbqidwsowkiu.cpp" ,"spaghetti/waylkzwxtgbidmkdweqcfjqidbowczukjouljtipwqlvigevgl.cpp" ,"spaghetti/ihoofolunrlvskocsywoukosinnbkpaxzuzhftfxhshudfdkao.cpp" ,"spaghetti/xvahbtjjvkpqzrkckisvayqpefpuvickvnotxvogaxitzxbgwi.cpp" ,"spaghetti/jihvznizyitkfczmiafpgdkfgyaesriwkrytlwijmgvfpuxgvu.cpp" ,"spaghetti/lfjecqkeydvtcwlfoyrbpdgmafzxlopiakaqjakibldecjubdi.cpp" ";" ,"spaghetti/ltmzkcfhwjlrqkfffxxxcoqfdzidyuvfjaokgygzcljnixicbz.cpp" ,"spaghetti/bqzkgvffdfhrszqlvnninakcjvhqbeijzwfnydwwtglgykxhzw.cpp" ,"spaghetti/kllfymqihabfltycymgnlpiaxozxomcotxykjnbpobwnuljzoe.cpp" ,"spaghetti/wyzjoqsonxvqilfmbnrgwbsfeiuwaxhozjkzuzfgswfihisfuu.cpp" ,"spaghetti/sbouurxiuswzubxyfeolqkdpubziwlueafsmzykssipqfxuvxo.cpp" ,"spaghetti/xwstxodrsgxitnhowavjvbggovomemfdaidradueaztxzqitmn.cpp" ,"spaghetti/cjtsekntqwpurrapyydbhhstyoifjukwxzxabxpjexntrmugsi.cpp" ";" ,"spaghetti/husvzrwzgzopxbbebtoogaditolzykyjrxpizqsaveauzopnls.cpp" ,"spaghetti/ncndrcvamcclegwaqngwqwbqcafubaddhqxyypztawuxvuvphg.cpp" ,"spaghetti/mdlxkhewfyeasmmnyehnnetgvvzvopzqjvwyoqbgiwfrxtcxqh.cpp" ,"spaghetti/otsyiqqbeveloechnlzoetjgtktqikpyaubeqxanztktogcjhj.cpp" ,"spaghetti/ehkcwmkcmxdgaggpavmiqupwozpgodpcarsjjwrzglhewrcyjn.cpp" ,"spaghetti/slidvnryjourqdimheqyhnvrvauqmoyrkjdwzhqlmjftbsqoil.cpp" ,"spaghetti/vqespsipwgmtpybzugsehuqmzgjykkkuymiemdxkiqtcnnnykw.cpp" ";" ,"spaghetti/pgxhrkwyrbfvmtzsxoswytkqrfqcqcgenjcayjbjsmoemvpwll.cpp" ,"spaghetti/qibumayhwudagzgftdgwoviikvfffiqnfojcbpadrfdoiqmnof.cpp" ,"spaghetti/dajuvuvjorxtynimplqoapbufoqevatxgsjvytuthifqqfgipb.cpp" ,"spaghetti/fdrtmaivigudyfdgiecnqmagssejmsbbsnonbgpafdodqkohrm.cpp" ,"spaghetti/uwzorjuciejsybhxcpctyxiltbkfoakxzweyhpjvribpushlpv.cpp" ,"spaghetti/cjlgzivlztepjbzdggkzfjiumzxtogypmhwasfuquovnsvpbvo.cpp" ,"spaghetti/vlntppidbnocskivishdathudeonivvzxwosgqhfcldfiyikpz.cpp" ";" ,"spaghetti/bwfgzqfvpkkzfqejtvwxtgsfqyiapgpblwbdetwugganfjjczn.cpp" ,"spaghetti/wmqtncdunukufhgisrwsvcrvkeilscncgibwqldgvypbxkpgew.cpp" ,"spaghetti/dquruhkoudkghasaacmdcqftlwbwmrbkxxuupsuxhyiuscuzho.cpp" ,"spaghetti/gjmmjsucmhbthkxajwvjeoeuqihdiziweniqjqqgfyvkwvbgxi.cpp" ,"spaghetti/ezeooitkshcihtopyinnyqqhudxbikffpxirkxxijqljfubgvz.cpp" ,"spaghetti/jbxozdrdcvxwwyxztofsipviqpcpbavcpjhbbvhleuoluhmrbq.cpp" ,"spaghetti/pljsvhocsjosyezyukotxedgeafowtomfaowtwrxpichedmimx.cpp" ";" ,"spaghetti/tsxxjyftdsmxkmnblcxuzbshobwriyaktpcxrrrrrarlbrzxyk.cpp" ,"spaghetti/nnzqptvkeadzmbapmuaroennmymsjvnidurgnebrrcvzjabhkf.cpp" ,"spaghetti/tedencqifdfedffsmsoqjgsrgaaefkkyfdiaijcqwntgfibzbt.cpp" ,"spaghetti/styvkckqykzqxsivfqibekrcsjsahjnuyjikutziflevdqwxyp.cpp" ,"spaghetti/jkikpxvxsxzwgweqwfviepiylqialppwbjwfvmqiywlqenrlit.cpp" ,"spaghetti/tgxfykdcnabiooyhtyjfkwysdzrrqskwcjcaaieldnejewldxc.cpp" ,"spaghetti/evcucgijsxpsurosqhcjnxyrihgrzhvdixgthdiznhaadwandb.cpp" ";" ,"spaghetti/wahvlnvxkkdfdmhmbndppmllybtsjdwxtcgapjatbcqogfvurf.cpp" ,"spaghetti/ecqploqrjrwmkxujydidfxrqllvqqnflkvvttxdeojdmphiosk.cpp" ,"spaghetti/dwbquzxfspvosalsntucpztkvukpecgpaaffnscqvqmjqwhqdq.cpp" ,"spaghetti/rytysvhpsshnqujrfivwhgxfepdnfmflaxhkdmhbunpvsnkcix.cpp" ,"spaghetti/orgjolhmzzrajyarmlbucfjgshjsfuartobcjojwpxiudrzwqo.cpp" ,"spaghetti/zhxkkgbshlcinugtqhumfmkwnkqdktrqvvbkeltthoyltvbxuz.cpp" ,"spaghetti/zeonxusdenewiiaelfvuaonfbzwwhyiabldpqjdlouwbqelmdo.cpp" ";" ,"spaghetti/oehtqjtzmvxxesgjfonhftsuliuqlixwqkyhktgpxwnpibprxm.cpp" ,"spaghetti/sarrwfrlxcsmzfjxzjovugonsycmxfhckblrifweliqndxpsmj.cpp" ,"spaghetti/ybcqlfqpsfbfeexfmdirixyffwhyobjldxwgzwdrcqxrphwypd.cpp" ,"spaghetti/uuuqggoyjqgkyvxlbeeipfthtdytatxvfxjmngbylfqdjmaofd.cpp" ,"spaghetti/mkhwklcwpiynaqegeohkwlxpzvpxxjjiipkrnqecmtqtbkgybv.cpp" ,"spaghetti/fvtdpgwteltlaffageglatgbmnmfxqhchvglzufcuflfvtmrcn.cpp" ,"spaghetti/ktjdfhmbpbttsjqtpdwotgblvuwpcpknfrspgxpdwzfghwbxjg.cpp" ";" ,"spaghetti/prlpetnwzctalodbgiphevhmrviwxbmfnlxgoqbkbhdffydkch.cpp" ,"spaghetti/waizgjycjfnnwrbnyvhiwibeixkzjjbutjzjizydhymxvhnjck.cpp" ,"spaghetti/tvxfvpwytwoplyrsiclwwocashgqpodopmvlklnnckankxsmsb.cpp" ,"spaghetti/ozloodrbjqsfpbvrqmuxojqzsviqzqhizpjylegxoxzstxtilu.cpp" ,"spaghetti/xfpnuoxoyglsotudygdvfgpmcenootcajwxgqamxujegyinvsp.cpp" ,"spaghetti/ndehrvbpvlqoxggycdvznbttntfzcgxwtesenrcxgpnsuzgqac.cpp" ,"spaghetti/oqzcoyoukhrjimapoizaqxnbjsxarpwuihsjrofakjltuzxmpy.cpp" ";" ,"spaghetti/wofwktofsnzybgfigjrvrbikbeuzifkxdfglskjwkipbwzwxvh.cpp" ,"spaghetti/vfupgtmjlpypzymhwygonmtazgnnnjwlvbfdapiviihbksdvsz.cpp" ,"spaghetti/rvoecjisnwwhbelpdpnrybhderpahzplayoctjervllcmxclbb.cpp" ,"spaghetti/mtpsqgezksgtjigfuprbiexopkplfsuirvxwmpbirzrdqrlqqa.cpp" ,"spaghetti/dvigbcuvlkctojemcyxzhvhiqjicbffrgrwaitqofcpxgjrwph.cpp" ,"spaghetti/yuejbikxqcvljygbtsnkltpaxuznqndhuroxhhtypypqgnyuez.cpp" ,"spaghetti/iydhsnnxzygigtwrxibgwtaxbqsvjhsgneqgusdufreajvkqkv.cpp" ";" ,"spaghetti/huxuflehxytlazchvvbmcffevjjimwolhprotardqeisrzosvl.cpp" ,"spaghetti/xuzygfpqdmtxefgrmyamcabjmcrnwgrqptllczdcvkdmjsshzw.cpp" ,"spaghetti/cddvgkwqzgdntrlvzavntltecnuwwrvkdlppzffddkpqaqgcjw.cpp" ,"spaghetti/yurvjyseeamxwpgbfupzftqxuceofhxosyyrgpyxlofpneyvyj.cpp" ,"spaghetti/giktbzvnxldwtkzozlhdleszokksanvhrqluqcdvqeqxguroaj.cpp" ,"spaghetti/oringgzrlamwzwshviefiiuwsutuzoqcevvdllljlynerarqpt.cpp" ,"spaghetti/hthamorrvrpfbhfnrrhkgbrpvyamfyqfqgdegzodysnokrhman.cpp" ";" ,"spaghetti/nwnbcycvilsndunjyynbmzoynocbvtqfxgnnrjfjkrwywpwnse.cpp" ,"spaghetti/eopornyfeawbbdxavfxdjmnzcmxhccnmvumeuvaircsvwxnzdu.cpp" ,"spaghetti/rxkrawbttrxcntwauaqjmxxynknpcfbalgpigqgumndgqihqgn.cpp" ,"spaghetti/cciqrlwvnhcrgmbdexqqvaihfevbwktfoslbqrcgpdqjwitxux.cpp" ,"spaghetti/yhrsgapuknrfiebjdrvkfiobmyhfexrivmparhnikuhhqsineu.cpp" ,"spaghetti/jlvrxucbsllkacpqljufolnsbsrforsyxwlryrkftgqwktqymf.cpp" ,"spaghetti/ppduzzkpgwocpnyhrmzlrebruqoszqqoitolzrtgjlyssrzunp.cpp" ";" ,"spaghetti/lvmpixokgkgilebsznqjuqjanflewvxivstijwrixketmcqjpw.cpp" ,"spaghetti/opmqmsaltrudcuczyphwjkuedyzumpwfvqdlbgwblwjbxezcsg.cpp" ,"spaghetti/pqxfvyuzblkfljhybghkusvgicrmunrzavrqrvkgolkgeiqzms.cpp" ,"spaghetti/zmaxarxlzczlwntyzcmubthmsbvvsmkgttavoauvkbbycynkiy.cpp" ,"spaghetti/cwxedbcdpdwijpzzbzmwbmlfcgvlsknxsdlrjlrqmdastnbjim.cpp" ,"spaghetti/ypbrzuxjmebdempdzvgynhsdmluaanpmlrxpsvpeewdduskeqk.cpp" ,"spaghetti/dyffozezioboomuzephpznrweshadylbqjtvheobbgnihlutwc.cpp" ";" ,"spaghetti/rggtlbwkkpaklxvxhlbryqalukfukhjriffdxeizcbhojxrzry.cpp" ,"spaghetti/yqtypuhaszfanunsrwzpeliswyttwfymqzgxryxioayudnzxxv.cpp" ,"spaghetti/xscqgainvdkrgoyoxuhmicdxfhivszerakqminhjizsyqsdhcx.cpp" ,"spaghetti/frnbsfdhrgubwrmqnwlfkwhxftozufqcvffwgxzelejmoymmhh.cpp" ,"spaghetti/ofiociypwdypfihzxbztqkivkvrsweulrtdogqbfrydsgpwffa.cpp" ,"spaghetti/aihlrlxdjxvczdkisqszbhjmesemcophvutnzpfioedaakccha.cpp" ,"spaghetti/mipzdkjhlzjrvmsndmzskuzcmrclpcztlczihrvfzsomwywspm.cpp" ";" ,"spaghetti/ilzmmstnxmoioubpldgypxpmsfkverekgnsqtckdpwwropbram.cpp" ,"spaghetti/adstpgpuygszvrvmkkizqgfhkzguuzaadmpsiuzuugyjywipfe.cpp" ,"spaghetti/glgnmpcewxeohdasvoatzyqvmzhrchclofkafrlgduuecqnhos.cpp" ,"spaghetti/zgfplmhvvnmoujgceorgrvqkctogznyzucfcwtiugpgepcgfqc.cpp" ,"spaghetti/oybevqvtjlsdhfsoqxwtwqjfbiwfothdukjhldyacypduoohkz.cpp" ,"spaghetti/xbaktmxdpzffodipymftumorplwxhogafchqvtlcuohhnhqsov.cpp" ,"spaghetti/nkfmnbopdxmkwdfvizyoesypbbnhpiucbfkihwgopgkoytjwbf.cpp" ";" ,"spaghetti/fnakltwxzgdelyszbkeedncckbhfmeojtbnjqscekichdjyrab.cpp" ,"spaghetti/fzyyaptlhgvbioekpmygkxmcskpocsmytzckvpqairxkvulcoa.cpp" ,"spaghetti/nwptxiiufxyqgqpeqbdbloorqhknhlttxlhdczwvvfyxctidnd.cpp" ,"spaghetti/fophmmqzrglcoritylaingbpddunacgmifyzobbqqkwxxmskie.cpp" ,"spaghetti/bxfhfuddbsohtbzognuyugbuxbelldhhgexrxricnxnrbgxbxp.cpp" ,"spaghetti/sllhgzrqkayquceibusjketzxrwzgvqqfwfvydxpjewcmgsbbj.cpp" ,"spaghetti/vgoumuewmarfvlainroxaclazblwjkdqfgyynbwkjgjojblgfh.cpp" ";" ,"spaghetti/avdnhuvnjelkjymvfzuzmhwwbnmqkelnbiczbgxsdatkgxwzmv.cpp" ,"spaghetti/ratxsljndyfupxrcnfyxbyvgqtrvatwuiuiwcbovvhoduvdejg.cpp" ,"spaghetti/jubpimicklwoicjyoejtwccayfzbwfzcabnzqgueqrjnbpafdc.cpp" ,"spaghetti/iniihtkpxokjroqyrpmipfcebpltquvwbbjkwzvscrmffqxlfm.cpp" ,"spaghetti/fzuxiohohxmonysnppwvwcapzgmogtocqzqskgynbnyycjswba.cpp" ,"spaghetti/klpxtjcrszbcxiosvuuaavajqhpinlsbaldrknfevjzvbvuryv.cpp" ,"spaghetti/wudsenasulrcxegsamicdeqprqspyucpkpilszvyhtiaojfotw.cpp" ";" ,"spaghetti/mlofwegjksrldkuxfcdtsrnifxkncshapoopqennvhovaqdoqi.cpp" ,"spaghetti/wkjdcxngxygtcxpiouyxbnlgshzectbfvjowxeibivltlmzgsq.cpp" ,"spaghetti/wsghevfralwjtlykilhqhhyepkrjzmozfspsmsjieinhuwpcqw.cpp" ,"spaghetti/nwihanaqvnhgqeszwdnsnuurcaaezxnjdxaeqttkfvotkcivrj.cpp" ,"spaghetti/wedslswcsjtwpclraadfrlnsupefujaonvchwwgdgesbxzozps.cpp" ,"spaghetti/lwyycwulmytmmktiedqfdtcjgmypilbhkvxgdtegcqvxbfcqms.cpp" ,"spaghetti/ngytslboprjksvyhbyqmthquxhtvqtqhsxsqfevgetosldgvsb.cpp" ";" ,"spaghetti/ampuoppblitsjihslskzquzrywbbhwcpndllnyvprxhnirwate.cpp" ,"spaghetti/uzwhyayjycuvkemiceojdorlfkvvqoeevxntgihfbuowncyaqz.cpp" ,"spaghetti/cuontyxpvcrtqerkymiyosoaogdsuajpzzykyckcfpnkvjeoek.cpp" ,"spaghetti/qgewajjzizrrdrjfntgwdyvsieeiekmkvnejowdvwigtsfmhxg.cpp" ,"spaghetti/haxiqakmakffdnxigpnewamwmafukrhwdynvmsrloznhrsqlsd.cpp" ,"spaghetti/pgotkchnktgmmjrcyobxmzxdxxcvxhvgmicuqdxrebbyahijvh.cpp" ,"spaghetti/mdnwigqgxxzyrrhzjzwkppromubpdgkrqegbguwnixzhrqnwrq.cpp" ";" ,"spaghetti/lvpftemkiwtmbstiduflkzzgsscrgdmrywwtxskxlwnblruzrn.cpp" ,"spaghetti/tjyececbpaoeyhvagabvlsozmtdjypkajxzhkzxohnemjmdnqt.cpp" ,"spaghetti/mhwobvsayzkzhsvmjxhottwwqylagmdtxnrqnxffhqqaqfycpw.cpp" ,"spaghetti/zojyxsfipcesugizlwhptowctgllvrbnhzygpvdwahvicxmllp.cpp" ,"spaghetti/gezbwfqbroufqacyvqoybbgszzhfrijveosajdgxbnoqobmtdk.cpp" ,"spaghetti/xuxveveixraythmufifwnuweqyugaciyxssudcikpbvxsbucox.cpp" ,"spaghetti/rbtgoxpcwsbbvhcxsjlejgbqyakovfgfqoskdgoudbmobctzmt.cpp" ";" ,"spaghetti/icwpvvkcrlwslkvorbskcrqrljvfbbphtlkajykutiqipfaihr.cpp" ,"spaghetti/ufsfkuzqitcvvbmxtgybiuzlcjdgqhcvwvzztzwxphdukczpld.cpp" ,"spaghetti/jntnzxrcnsbdlghgekquorlrzmfhpifsctachzwxeldxwkpgvk.cpp" ,"spaghetti/kblvfwvpssypwnddnflwusilxgblovgxxxftmkqxwxervawpwf.cpp" ,"spaghetti/bbufdmujorcnyobnpsqdfamkxgcambevfxmspiyhkeavcesmhx.cpp" ,"spaghetti/bwbliibackjirxhgqalvrqdacsmftpxxlhswaddfnntrxcnaqk.cpp" ,"spaghetti/jiznkuzyqnnyogcakahnnrogolwphzkqhlqibrumjxlgqqndzh.cpp" ";" ,"spaghetti/nltuwsvovnnbyyuzruptdtbkacnsybwerwixhuopryvlidocqr.cpp" ,"spaghetti/gosravmojqimxdmzicpcuxrslaqdqctetursdxckdcmepjrrce.cpp" ,"spaghetti/rmtluplczfuljozpofrphlukpddmfjiizegbbzivddjfpwrdcr.cpp" ,"spaghetti/xfrdlxqwwnalcatwlbnowtsldnzhtlllgltggplmldwjisanta.cpp" ,"spaghetti/frptkkujjbbumvhtpksjbkceclpzyrjlqpcqpzfahxyzoizfkq.cpp" ,"spaghetti/uerihkjhdcbjyineokzzgcegdkahrxsgjhqyjoiuojuajidqmx.cpp" ,"spaghetti/vouesxookdgiwbpexndbgghfogzkhbnccwyhilmhxilrjwubdf.cpp" ";" ,"spaghetti/yjmcirqjeljkcqvumysqdbsyrspfdaojzclrnnpcergbrgnlhe.cpp" ,"spaghetti/ukknoqfbmhbdbrjmfmupqcxlvtvkzlzusywhccksiphrusjrdu.cpp" ,"spaghetti/mgflljjhyadpmyfwwtimodpgieifiqgcdxlelsxrojfxurjryc.cpp" ,"spaghetti/fjdxhjclajlpkxeexfqilblqzkmlbrdexrluigacysijgmkkht.cpp" ,"spaghetti/abjhpkzlvkoxakpkmumttqdiuxqcbwaohrlyttdyrwjucgosuz.cpp" ,"spaghetti/vztlyrwmdgawiskpxqkvgdkweabcxfpfkenxmbvddnjqhadiwx.cpp" ,"spaghetti/puwxardezfosnwavxvzzdvssuobluzzuwhdbeamwdykmlgzpfa.cpp" ";" ,"spaghetti/besbjhaewjjmkigugwxxgdjvhlvispbkganusyvwuhdrkmqjij.cpp" ,"spaghetti/aoussaasimomkkbhiycxossxxhbnzbdxhxxmoacxbkyhkodagi.cpp" ,"spaghetti/wsasatazywgdimftwdqfkaxxpciwabfiesgfpjhsvsvhrgalom.cpp" ,"spaghetti/yhgukerttxrthqsqcsirujdnwaubicfytaqyvklrlmlouzdcys.cpp" ,"spaghetti/yaaagmeplurgirnrehymcswlmvomqympkpkwnftybfmlieodsh.cpp" ,"spaghetti/ocsfebrsfhxbyhwjbhonzbpzkzldcypvwsrgdjosuujxwbzrek.cpp" ,"spaghetti/kxeejacnxeodaulyilmyiwnmvtwwtuaelxxlcgzwzsdeelivko.cpp" ";" ,"spaghetti/tnizshkgwdrmbqpaemfahmyrsuhousgpqngckgxztmsxndbaih.cpp" ,"spaghetti/pzhlljzvdmsndxtlcldgwlzvubsgqvnxjhnatlewysowbnnapb.cpp" ,"spaghetti/oagaxkjcumkovvglenqtradzrwjzdfshoypmaxvldvqcppxqlg.cpp" ,"spaghetti/ydtecufvkqyoqomctnmwxooxyfwglxapyikilpywnradmexjvd.cpp" ,"spaghetti/vouxhnzagtawvobkrxswwffozmmbshewuprpqcxzvcnuvypbzq.cpp" ,"spaghetti/oahkltgvdbhknpvhaticbxpxdvykhjuvakrlifwqwwkthqslaj.cpp" ,"spaghetti/ggrqqidaureotqwbxcealoguqhqajiainmodjjapnkqdzvivft.cpp" ";" ,"spaghetti/rildbbicriftffvukugmupmcokyxzdjkwohaaqelekdngirply.cpp" ,"spaghetti/vnuuqkknrcumyiexddgbpmkgzpnahbzgmbpilhceowrbwepfpf.cpp" ,"spaghetti/dyvvhbajajtxfdpfmycpuucmagfuvzxryqltucxvqffdokbdlq.cpp" ,"spaghetti/rjefhjscbuosaugjsexbubghcnggfxbbablaseraiwusflhilh.cpp" ,"spaghetti/rvtigabhzuxlqmdyxvbfrezxwlddwzvyoqbrkmqnxtsnbobias.cpp" ,"spaghetti/hwcoujebtkxitvgqncaibwsnuhvnjljutyoowbnldciaozeeex.cpp" ,"spaghetti/rjcawiukreoekycvuynpvoljpwbuhvfyiyrqmtfnmyqfnwrvtw.cpp" ";" ,"spaghetti/wftirwwdelebqizcjinabqoaazwjctscufmedibutszivdshys.cpp" ,"spaghetti/nakrhiukvylugacxwlfbmtbyriwzlmjpcnqugjmupyrrmyaziu.cpp" ,"spaghetti/skplgestdlylktegqvuxbhxejmylzpmmmgkiiyazfdpvwqrptg.cpp" ,"spaghetti/hkzayynlzftcdyvocawfgsaxdvztfvkevwcsaltektyjjrpccx.cpp" ,"spaghetti/ihicbkrxbbozbjjjtqmpjyqjizdmnxcbyjnlgwvlmorofrazqa.cpp" ,"spaghetti/axbmnoauajcrwrznqxlfychfjkyelbsbfztrxshhnvqyfqsncx.cpp" ,"spaghetti/owzfayuijvlbjgrrybzhcepkfybyzstkzswyktoxqmfyyblyps.cpp" ";" ,"spaghetti/gtvhkoebufkwfdorykesjszuifvcyeyudogwyunvcybpeorxax.cpp" ,"spaghetti/jqvyfnncicnugpzwqnvxcpzroetbillskvmpmlugpwadkyqxci.cpp" ,"spaghetti/lnpmhxymcvwwiudxdchdzkkktytruxnyluhndbgbhvwvdsdxny.cpp" ,"spaghetti/alfgurnlfbhtbnkonhjztbiqmiviolkdsfoattjvhqlvkltirf.cpp" ,"spaghetti/pgfbbhtmscucbumqyfmejjjjxcsyrnaervxijcfkebraucqmxn.cpp" ,"spaghetti/qptcdamtstoxtnpwzlchtdcetjlnrtcjqjvpasqeychhrbhfvd.cpp" ,"spaghetti/ilczflwaebdpceorzgwrhnvkaqusxrsqtdvusrsizobywpyrbv.cpp" ";" ,"spaghetti/yhcajwolkrwzyyriglxmbtqagjphzxckgbkalzihclkmfzqcfp.cpp" ,"spaghetti/yizmrxkbkwfwkzranitohqdfowgvqlaqqtpzwuncokppbhlwsr.cpp" ,"spaghetti/xikiqjnkwcdbdrjytlilzfqpuznbdzbjefotytquwvghqmxkbf.cpp" ,"spaghetti/ohbqpuxzgurdfwubnsrffejvdbnyatbhvfejlccsmebwnnqtwa.cpp" ,"spaghetti/ixjapazjvmsuhfrfyhrtmgjwiazbsecrbzpvtkfiqxhogaurzz.cpp" ,"spaghetti/ezxiocglvjywjnneddfodcdnhtibguxukrpqvgggkkjdjunkyh.cpp" ,"spaghetti/prslazobjlmflikkckpytltdrcqhwdrlrfokraqryrqgobgkes.cpp" ";" ,"spaghetti/rufrhreioxuczpfircwofokjnwaachspdsbdohfbbocbfoydnt.cpp" ,"spaghetti/rikkxahijvghhzzeckzjcyoawibiekuzgtwytdsnlpebklgvtj.cpp" ,"spaghetti/ejhreavpafujdfodobgkhpfpmnltohbxrbhdxwgjukmdbhgprg.cpp" ,"spaghetti/qhebxfmcxonvcyeudwyngfipwpxlhrbxjvdrlxjuqtzkqyiajt.cpp" ,"spaghetti/vyhdouazklkocpnvfckzivezogttqpanausosaitkaybzbhwer.cpp" ,"spaghetti/moanwsapmlcijsqzdzyxekmnhebapujbhrnuirijjvbscfhajr.cpp" ,"spaghetti/aknflzkydoiszckudtoftajnknykyjotpszuugdnzvejqlwmuo.cpp" ";" ,"spaghetti/acgpoytkwegzlcdvvrpkxxsvqocbaelpfsupfqzydsnwunvnyi.cpp" ,"spaghetti/mrxjzydlekitdybqrgrgyhveovtylqokniawgmlnxqmjqkzqxj.cpp" ,"spaghetti/yimjppojhgxjuamipdzuxsjznbztkiohdosefeupngsfnqcgnr.cpp" ,"spaghetti/iqttoeceatvkvvgkiaqzgxupchrthuwdzrbgqhfgvrwtakxqaz.cpp" ,"spaghetti/gfppsrxvovgsyfyfyrfxftisvixkkjctactsmmnkkmbetrjeyv.cpp" ,"spaghetti/ntfklmzpcrffjofyiwibcwrvhspbxuigselwutxdrrswejgiso.cpp" ,"spaghetti/indgxkzlifvytonvunsgwikbjfbprtxiaksowqcfpqkjzslrgg.cpp" ";" ,"spaghetti/yzyazifefvqaqifxlhdkgnloiheknsyzgfalfqpudcfwfeeaek.cpp" ,"spaghetti/kvepzqmsspotjdswqwodlaadytnawhnjfogfztvfasjzmbqwcj.cpp" ,"spaghetti/mlofjmeqolxlnpjvfvokbncnlyfnmcgofpckzwwvpkebxwkbws.cpp" ,"spaghetti/jhjsysljnsvsyikrxgsiouxjptjmowhgdsklhqrwykechmbrhh.cpp" ,"spaghetti/ronplmlxtmojcemkomrlcmwjkzyryvfdyvrouixuwmjxnyzory.cpp" ,"spaghetti/bebiijyorbzdselpxdlocnqaebxkryxmzewiygwoztjdtppxdh.cpp" ,"spaghetti/uddrcxkoyqkdhjdepglhvrwoavlogevqbjoiuzpxxkaooepogh.cpp" ";" ,"spaghetti/qyeejnkpuxjhskdbqvxjirdutjisyhfsrqmptmjvhezrmamzuc.cpp" ,"spaghetti/klukknrhamphkhwimkzvpzssaxkwnpzqvwumiaqknbcmconfei.cpp" ,"spaghetti/jahyrzwfcqdhwdfszgmsakydxaiboquxryedsaddvgwxbizdsq.cpp" ,"spaghetti/zmpsalxhzsfjzhthnllevnedvvfzutudckpmndepqxnluyfkpi.cpp" ,"spaghetti/cmzumlhzvogucgwqzukwzhrswjtkqepdarwfavindcdoerchub.cpp" ,"spaghetti/bhsjzimbyaiuykirqneslvutpuspmibmgplopxtnyowebyoaxx.cpp" ,"spaghetti/khsulbaogfhxzcmcbamqtnhzotuuguybinnvdnxgcadrdmpewm.cpp" ";" ,"spaghetti/yqtekuvggqlzflqpobvqjlifkuufrwgvsbtwwhkippcknyyizj.cpp" ,"spaghetti/hrfcgfailhtpjmoqpbiobdovudbhpiveyloqchzllugmsesnho.cpp" ,"spaghetti/xkjslwxouqvkfqtcbkcxcgkadfesyqodhqyeejlsssrquutarp.cpp" ,"spaghetti/vyigfhexucvctceoldfqxxpfatfkwkdeqjcnwdkigxxtstnuzh.cpp" ,"spaghetti/kiztvcbubikavrmhuhkosxaglptniytcfobpzmbxpzzphhuywy.cpp" ,"spaghetti/jvhoaxsdzrtwxyyvsgmyoqwjkuvhotvcrxmmztnkbcebntnafw.cpp" ,"spaghetti/igxueswwwislzogygjcypsbyawsnkitckjfonuwmfodrgwqylc.cpp" ";" ,"spaghetti/rwdqeempachkiopyhewogfbhgwytwkflknyxnjtfzeqfqrsrzt.cpp" ,"spaghetti/olimwlhvlpzgvsjboziizmpyikzlysjokktrooqgndfgnlmota.cpp" ,"spaghetti/xciqktroxxkwsnvjypydvkweouvkwcwybgvlypergjqeqbqdry.cpp" ,"spaghetti/ypaeykpekaeuuxikxymfcyeeyryyqogxyyostgmdkdqmuwqdvl.cpp" ,"spaghetti/ijikprkoqqvlaofplanbbskslqxqupqzxfnslwcxqufmsaeiof.cpp" ,"spaghetti/flluoynnopsntybxybyejfbrjazttwqbvhfkphteizvlcbzinn.cpp" ,"spaghetti/wiebjuqhosmcjxzckbwgptsxeacazpoumvrgbtneenbirsthlh.cpp" ";" ,"spaghetti/ezqrzcvzoovqdvgifpmepauqgpfkvmjlcivibsgrptbhtngqnc.cpp" ,"spaghetti/btdayaeyvhpnjhhddnlyktlrhgjiuocsxwuxyzfyrhmniolhjw.cpp" ,"spaghetti/syiksteyzsfjkndhbnprpntedaesvneksxzmvzatvdcgxxaqla.cpp" ,"spaghetti/ftcckoiqdlcevpjgwotimmnzqenokcdpqcqumivqhtbkyeuaye.cpp" ,"spaghetti/ryswavthrchzjtzklmipsuzxqaykbjpeyofrjgbtctgbebsqmd.cpp" ,"spaghetti/tcpqfrpfyiyhbdxpogpwqvpazigbdxdyomlsoyzwmrxucvaicu.cpp" ,"spaghetti/prfutjyoprztqtgnnvmuiyuczowwgqgrwnujibrfjcbhbipumq.cpp" ";" ,"spaghetti/flwqsxlptxetyiwjtnwxxegbguqaldzvxyyohcvsdjrgcwuloh.cpp" ,"spaghetti/scgzpqoarnobedaxqacicckvllbcrchttdjsgvcflcezyriyaz.cpp" ,"spaghetti/fcfvzozumribpfqxggnngfecsixppbdbxoxjlafdulkfgmaibe.cpp" ,"spaghetti/npdyziqmpqekrhdpheambyhisnegexsbdxsxzttpljutnubimi.cpp" ,"spaghetti/uvtxlrnfhvexnqiihhzqvyturlthirzlqmuwonbqgcfryxfvmx.cpp" ,"spaghetti/bwsocoopydvtabinilcxlmywukssjacoglyugznmnkgrvcuxlk.cpp" ,"spaghetti/gjbdrmdtcxroomiyspadyqmopfxljjpdfgngugvhkrufiqzbwy.cpp" ";" ,"spaghetti/krybwrwfstxaezwxmkayhjmxtcvautovmxjgekpnwwombilhio.cpp" ,"spaghetti/ncxtaeauimhrwcveowaealoixmrvpfkgbbjavzmalsakkxkmah.cpp" ,"spaghetti/rqgklfkhnovguarsdanhtjsvomsuzxfftdfhkvichpqcrfbhmm.cpp" ,"spaghetti/sgflvizqvdlyzegzrpoyulorhpbrokgiybqyuyumjljlhhwssg.cpp" ,"spaghetti/ksswxhjlrlgsxihflgdrovxfnvksvssmwskwaltqdtvznduzju.cpp" ,"spaghetti/qodokwsdtmzhpyfgcovbaonhafknwbbsopaqlskrttxwfzldhq.cpp" ,"spaghetti/ldffqiblesgnctgxlpdrpmbeodlqfnuapouqjhlcqdmmsfdtlq.cpp" ";" ,"spaghetti/sgnimoncptssuutklgtlcntgrepahzprjnmsvfwbzvcfnrupok.cpp" ,"spaghetti/xcyayumiuivakrpelbxpnxghjzjaoctgmfimnafhdzieeceljs.cpp" ,"spaghetti/qwlwszwgjuzzwkcxkdnojqvydgvkpyqatafphhnblaizycavdo.cpp" ,"spaghetti/dqzauekrnzczhrmqjsrfgthksfsepxjhoeniyedjgbbgqvnsfb.cpp" ,"spaghetti/ibgtlivtxmdoszzxndgryskmmiphxvohwmdmqxwvnqoaaoawjk.cpp" ,"spaghetti/ygavcvzsgtgxceuyqfwmlxybdorobejnmovcmbhprnzdkduldl.cpp" ,"spaghetti/uximdcrsxpfosrxlztonbwpxahwetyhkjkqmngvrxqyfrhbtrh.cpp" ";" ,"spaghetti/tmgaxrjumftbnedsdoollafrdzxnuqyiuhojzwhasmagpcaagh.cpp" ,"spaghetti/uvnbesjngbewzglfykjwrvqzshjhzezepcqgaqermghknoltiz.cpp" ,"spaghetti/rtfuuvbljlxzofzeomsxrustzhewnssywsopjmnjvoiphdzgls.cpp" ,"spaghetti/wgtdpbvpvyvpsllcwmazycghzhzbcoelefytefapclgdpoggrn.cpp" ,"spaghetti/rqbfvvvcalhqrfzwkorzjjwcumwxaygvmguazfabauwxxjxnow.cpp" ,"spaghetti/mzgcfbajvgtymufrtxroiowuzbcoftanfqyuugoqlwrgbubkqe.cpp" ,"spaghetti/smsohkdnzcwvsrfnkpqwmoxlvwjabsinsecaqhblginypsqsup.cpp" ";" ,"spaghetti/pifrgmpkgwrniduoaawvlhflllvlqmfgdcblmxjlrqduvubkbo.cpp" ,"spaghetti/xzfjfhncahkikjalzqcnyuhhxjxuifhulamvgaqyvzhcibvasg.cpp" ,"spaghetti/tkafhlaqnmyzfrgkovsiqxlthzmddfivevgvbdufpokoezbbno.cpp" ,"spaghetti/uiifhqicvfsrvdlhzdingqzklrqxyvmojdbmelagiklnngyoav.cpp" ,"spaghetti/yndeqskqxkcyhtbcmdbyhioiaxttxxbtriwenbsxcewrvjpdos.cpp" ,"spaghetti/lrcgqhbnutkatcdmiqdfjqmhgvauqsmclftytgwrayxhicuomj.cpp" ,"spaghetti/dmvmitbjinequhanfgywqsgsujftmaovpgbvsxqmdxikcvmcxr.cpp" ";" ,"spaghetti/xlxbuwvvbrgrogogauhttbolaepqegbzqxhtfsdsdvhmbcfzoh.cpp" ,"spaghetti/naljewoqbdexeqdsehwhauaqobkjhmyxabkimbftwvphmfperh.cpp" ,"spaghetti/oqbhqmeorgvwhqqcotvjgfynaybfsbcvcpnwcudnyguyigkkch.cpp" ,"spaghetti/bfafmbskvfehctsyfoeubmfhqurjmpfcgzvvhynnbrxeiiruda.cpp" ,"spaghetti/hqorbdikhrkiesjkpqdbyfazekqontcerjwvxcbljohfvjanny.cpp" ,"spaghetti/qoktjshpnupifwuqkqtohcvyfsupncwdlajyjsmvqxdcoidnfp.cpp" ,"spaghetti/ajgqzrmfnfvdxmdfafdmygvguaurpmsyvqdmldjyuydqcvbieg.cpp" ";" ,"spaghetti/ytlcmymtbyslsdzztpemqphobdcxqidilgkzjbhmnvunfqscvx.cpp" ,"spaghetti/vetwaxjlqmgrlqoqetidkamfcgcdegmdjgaueinhbqspbrqxql.cpp" ,"spaghetti/ypdiccpehzbrtiqkvtelehbfoxstjtlcsqeqgpivbgnnshjjfq.cpp" ,"spaghetti/zblifiikrthfolbsbizugkwjaqzuoftmmgihkeuzrezfwxdrgl.cpp" ,"spaghetti/chpdpqemeebqpcrqolkzgxonkopjspqdcfenwtdoqbayjizgzu.cpp" ,"spaghetti/ljlemzvwdiiidagrftkqaofdlxfhsjuxeieaykjawryucjoatn.cpp" ,"spaghetti/lugbrvtvqrhrnuooxdnrrknhobxpeadhrjtcdjabooqezdrnno.cpp" ";" ,"spaghetti/retsncxxoihfrwfvmznlzjadjjvuhbpcjmnxtodokpbdzgtfep.cpp" ,"spaghetti/rmcrwbocgqntlctqejhojrhzvbdendgwlvlqngabjujylsglhp.cpp" ,"spaghetti/msniqyqwudqnczwrkywxnqtvwtqmnxrgqufptcndwylbrzjxzr.cpp" ,"spaghetti/oglbcurahirgekwfjtbsrbfbqdyasstlglwxrbgebcmmmdziry.cpp" ,"spaghetti/tldaiebewrtiiwvspoyapucnirsukqyvwhfvswkvhetjqucpim.cpp" ,"spaghetti/sztexwoxeyocvvswbgurckfiabxmendvyszjfpplhqppoikzvn.cpp" ,"spaghetti/ihkgahsnhqjahoeaovosemtjtpanzuhladilwasagansldhkdy.cpp" ";" ,"spaghetti/pmlzzwdvyvwydvyizgjllsjrjccvdvhpmfxxtlrtigcrtracpr.cpp" ,"spaghetti/hfskleslkaobvyxnygetzmjcslpbmtffqzcvwmmcxvbuhlvcxe.cpp" ,"spaghetti/bvvwfywaffutdjeraqnbeerlnioaptyzfxfqqygvwxwueatmwr.cpp" ,"spaghetti/gookrancgianttrhxcgteszwqqmenpzlufeovtglqggioabzdh.cpp" ,"spaghetti/uehbpyxmbpcypivelhdojbujvanhtyccpndwxearoeamnxgzcb.cpp" ,"spaghetti/gsczpvzbhaooswdchutcsmxsfaimlwfeqcxmjbpytlskxatash.cpp" ,"spaghetti/lvlgxutzyamikczpcwibbcvjuxaykeonplfvldqgubuebdtzhn.cpp" ";" ,"spaghetti/tstxfhgunalmrtaqapebujxeghhgnpkihsyoswzcivwsktnpgz.cpp" ,"spaghetti/yyfoppksjainlhuvvoxplvjvdzjbszphrazpefpjknjmfqscyq.cpp" ,"spaghetti/sbkzigweceuduttbqivdkknsllzxliorwbsxpeqzmgxpgexsid.cpp" ,"spaghetti/aguqnuqtekdwmcyocyjrhrwdqylrptwemvnamejtrckkzjvpoc.cpp" ,"spaghetti/mhvnzraoouqfdklbtnxreqaehopvttktssthinivcryikrybsf.cpp" ,"spaghetti/gbpescgnyvjwcjnstkafhrzjhxfbztfkqxiskoldcyfehhbcxi.cpp" ,"spaghetti/wpnxifsfsmnyeuvgsmpasyhbyqkapdzyxphxtzimhxqsykmpwb.cpp" ";" ,"spaghetti/snfennmcapymvrlpnpclbgzksnveokzdwpzxfyuudcrtdfadre.cpp" ,"spaghetti/yfmjekiwcxqshivjdirxtgxoifjwrgtxvcofqjbrhsiijjskej.cpp" ,"spaghetti/siqemdmhhcqtpudlusyulwmalkwxegzwgxniamyeiwrgsahcax.cpp" ,"spaghetti/vtiqnmyyzcpynefvdpqjmnjwhalninuzqgymbbzrnlgxquzlqv.cpp" ,"spaghetti/jpsrkxielxlehdnydwqpzzltxlfclzakrexgzfoznpnddiokys.cpp" ,"spaghetti/lfjdrhjmemmltbcbcttnkhcjkuamwelajyuundxtwjcvevyvqq.cpp" ,"spaghetti/rsgmbkoijkypavinssrpeepnxqpyzfwtbqvewokcsravedzzpc.cpp" ";" ,"spaghetti/tdnszjrmzbjbkeobcccdpbmyamqzmtpwwqyntoyoovsoyqewic.cpp" ,"spaghetti/jhxmankhwqywbmhbuxvxigpqqsifcvzsmxbjztxkrlpzsdnhdt.cpp" ,"spaghetti/kllprmlvmtyhabctktipmbzqcgywkozaoripgwewaqcqjfojmg.cpp" ,"spaghetti/chzvdulxylcdzixzjlrgovinsrkctbvcvwoauhmsjuycqhsrrp.cpp" ,"spaghetti/pzbzstzvuswrmfqyqayfhgzkffpzyilhxlfwkzjgdvgixpdqpc.cpp" ,"spaghetti/frknrkeibhkzsaiqekupdirdmwizjzlygncjqptdxpgavniwyn.cpp" ,"spaghetti/xpjzpkblymgmxawatnjbzgkfromvujigstnehzpcagjtxdjfyo.cpp" ";" ,"spaghetti/gpymetgeyyiwmqtxczpaglghbxufdvrungjldlnjajvhyagkju.cpp" ,"spaghetti/yxihqkmsrmscbdztlaxnzhhyvflhxjikqpnyufdzlsynqucwyk.cpp" ,"spaghetti/iysgeitcdldgxnkpocrechiwciwhbbbctrkusxexermdbreztb.cpp" ,"spaghetti/gxwmzhiikdukcxobwzmarpgtevotuwzwpvyjpcqsfefjzzwxrm.cpp" ,"spaghetti/iaecvlqktgkbxasxhsilsasqtlcwgqnsvvuhxykdfcvdjcvczv.cpp" ,"spaghetti/plfrsfbbbgjqxxlthmevilptzbdjbktcvrclxaniyvxbgiptek.cpp" ,"spaghetti/slkujtdknpyndridmpwcgbvxuawscfrljstfwvpmzxycfpbpvq.cpp" ";" ,"spaghetti/cbznfaqlcsxcunadomamqfwspjhsesjzpoxxbnoejxdwjfnecj.cpp" ,"spaghetti/dhokpbpcvzqlsolslehczhyqudugoqczubzjshwlrvsmnnsbji.cpp" ,"spaghetti/tcjbyqgtoylnpctxlgbcysapjpvqllgwzureosicdambypdocy.cpp" ,"spaghetti/qxecmpoitqtpdyeumdbdfdyidxnbndzrnlviojinuqyxyglucp.cpp" ,"spaghetti/nebwpbpbsokfblfcdoqptvnlakmjhnclhnqqplrsslbcomoxff.cpp" ,"spaghetti/khgyjkyieeaomicojuzkewykloeooejjcauiubrljhpjiqrhjy.cpp" ,"spaghetti/psotqgfoicptyfqggfkwhkjwyaqvmzmnbqjohnzwmghjnaxfve.cpp" ,"spaghetti/znxmlwbedrctssyajamboadihyziwjpezyglhemygmjesdiycp.cpp" ,"spaghetti/ekvebarjreidkaxcssntrzdwhvtzlfjgjszsoorotnrlrncqoa.cpp" ,"spaghetti/fmcsuuahfryuftpsmdmyfttnnftyqjizlshaurgjlobhdxnlyi.cpp" ,"spaghetti/nkkdzjjfvwopooqnlcivscopgvvyjvoixfpzpyajtwlxmszbcz.cpp" ,"spaghetti/ayvgnofqweiesllskmpithbwgpzuekbthcbzmwuwfgbszwyscz.cpp" ";" ,"spaghetti/djoodumzqpuejednbfofcqohalvroroxsdeqpjtzywxopvodhx.cpp" ,"spaghetti/gitqhgznnkvhcvwonsbljbwzfryfdjwrveupckassrafhuqudw.cpp" ,"spaghetti/oqdoesjogfnmyorloreqdtljzzfaofqfexbqyhiishvujfmqbx.cpp" ,"spaghetti/zzibjedgygsdnzkclvzmqyfqvaqozqpnutrefnlgmqvcmimlha.cpp" ,"spaghetti/utvmyapvbtlkdnhqtdquzzfhcvylqifvbpnnkihdjxibxlqalw.cpp" ,"spaghetti/ysdhhqwvzmrgwlgzoomxnbhofswnshmaxtivntzyhglvcwgfsn.cpp" ,"spaghetti/tzcyzmfzgpwlmmwzjyztyedvtjwnafjcoebiqpllbkcgqrtlku.cpp" ,"spaghetti/odpeswpyfiutfonuaxezaffpnvcsiualbyjpszbatalvtztiwu.cpp" ";" ,"spaghetti/gjzmlkoxjnastqhmykroyvvycsvujbspjbojqyydkfampwrujw.cpp" ,"spaghetti/xhfvwsawrgulvmvkkxnjknpngavtbmikgmbmlbdtekqcioyyey.cpp"]

for s in a:
    if s == ';':
        print(s)
    elif s[-1] == ';':
        f = open(f'{s[:-1]}', 'r').read()
        print(f'{f} ;')
    else:
        f = open(f'{s}', 'r').read()
        print(f, end='')
```

Then, with a little manual tweaking, I got this:  

```cpp
#include <string.h>
#include <stdio.h>
#include <iostream>
#include <stdlib.h>

using namespace std  ;
int main() {
    string _ = "Code that overuses }{ GOTO statements ratherzx than_structured programminjg constructqs, resulting in convoluted and unmaintainable programs, is often called spaghetti code. Such code has a complex and tangled control structure, resulting in a program flow that is conceptually like a bowl of spaghetti, twisted and tangled.";  
    cout << "People always say that my code is spaghetti, but I don't see it. Can you help me find the flag?"  << endl  ;
    string ____  ;
    cin >> ____  ;
    string __ = "";  for ( int ______ = 0  ; ______ < 55  ; ++______) {
        __ += "a"; 
    }
    __[ 0 ] = _[ 63 ]  ;
    __[ 1 ] = _[ 71 ]  ;
    __[ 2 ] = _[ 34 ]  ;
    __[ 3 ] = _[ 66 ]  ;
    __[ 4 ] = _[ 20 ]  ;
    __[ 5 ] = _[ 71 ]  ;
    __[ 6 ] = _[ 5 ]  ;
    __[ 7 ] = _[ 51 ]  ;
    __[ 8 ] = _[ 71 ]  ;
    __[ 9 ] = _[ 15 ]  ;
    __[ 10 ] = _[ 51 ]  ;
    __[ 11 ] = _[ 128 ]  ;
    __[ 12 ] = _[ 7 ]  ;
    __[ 13 ] = _[ 2 ]  ;
    __[ 14 ] = _[ 51 ]  ;
    __[ 15 ] = _[ 255 ]  ;
    __[ 16 ] = _[ 6 ]  ;
    __[ 17 ] = _[ 3 ]  ;
    __[ 18 ] = _[ 34 ]  ;
    __[ 19 ] = _[ 51 ]  ;
    __[ 20 ] = _[ 56 ]  ;
    __[ 21 ] = _[ 1 ]  ;
    __[ 22 ] = _[ 2 ]  ;
    __[ 23 ] = _[ 3 ]  ;
    __[ 24 ] = _[ 51 ]  ;
    __[ 25 ] = _[ 71 ]  ;
    __[ 26 ] = _[ 15 ]  ;
    __[ 27 ] = _[ 51 ]  ;
    __[ 28 ] = _[ 3 ]  ;
    __[ 29 ] = _[ 7 ]  ;
    __[ 30 ] = _[ 15 ]  ;
    __[ 31 ] = _[ 71 ]  ;
    __[ 32 ] = _[ 3 ]  ;
    __[ 33 ] = _[ 13 ]  ;
    __[ 34 ] = _[ 51 ]  ;
    __[ 35 ] = _[ 5 ]  ;
    __[ 36 ] = _[ 1 ]  ;
    __[ 37 ] = _[ 51 ]  ;
    __[ 38 ] = _[ 13 ]  ;
    __[ 39 ] = _[ 3 ]  ;
    __[ 40 ] = _[ 7 ]  ;
    __[ 41 ] = _[ 2 ]  ;
    __[ 42 ] = _[ 51 ]  ;
    __[ 43 ] = _[ 71 ]  ;
    __[ 44 ] = _[ 34 ]  ;
    __[ 45 ] = _[ 51 ]  ;
    __[ 46 ] = _[ 7 ]  ;
    __[ 47 ] = _[ 15 ]  ;
    __[ 48 ] = _[ 15 ]  ;
    __[ 49 ] = _[ 3 ]  ;
    __[ 50 ] = _[ 32 ]  ;
    __[ 51 ] = _[ 128 ]  ;
    __[ 52 ] = _[ 93 ]  ;
    __[ 53 ] = _[ 276 ]  ;
    __[ 54 ] = _[ 19 ]  ;
    if ( ____ == __ ) {
        cout << "Congratulations, you have untangled this spaghetti!"  << endl  ;
    }
    else {
        cout << "Not this time!"  << endl  ;
    }
}
```

So it seems like it constructs the flag string, i.e. `__`, from the this initial string `_`. Then, it checks it against user input of `___`. Well, why don't we just add a `cout` statement before the program ends to get the flag?  

```cpp
cout << __ << '\n';
```

Now running the program returns the flag!  

    ping{it_is_bad_when_code_is_easier_to_read_in_assembly}