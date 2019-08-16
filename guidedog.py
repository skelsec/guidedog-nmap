import ipaddress
from ndiff import *

def print_table(lines, separate_head=True):
	"""Prints a formatted table given a 2 dimensional array"""
	#Count the column width
	widths = []
	for line in lines:
			for i,size in enumerate([len(x) for x in line]):
					while i >= len(widths):
							widths.append(0)
					if size > widths[i]:
							widths[i] = size
	   
	#Generate the format string to pad the columns
	print_string = ""
	for i,width in enumerate(widths):
			print_string += "{" + str(i) + ":" + str(width) + "} | "
	if (len(print_string) == 0):
			return
	print_string = print_string[:-3]
	   
	#Print the actual data
	for i,line in enumerate(lines):
			print(print_string.format(*line))
			if (i == 0 and separate_head):
					print("-"*(sum(widths)+3*(len(widths)-1)))

class TableRow:
	def __init__(self, address, port, service):
		self.address = address
		self.port = port
		self.service = service
	
	@staticmethod
	def get_row_hdr():
		return ['address', 'port/proto', 'service-name']
		
	def to_row(self):
		return [str(self.address), str(self.port), str(self.service)]
		
	def to_line(self):
		return ' '.join(self.to_row())

if __name__ == '__main__':
	import argparse
	parser = argparse.ArgumentParser(description='Nmap XML query')
	parser.add_argument('file', help = 'Nmap XML file')
	
	args = parser.parse_args()
	
	table = [TableRow.get_row_hdr()]
	
	scan = Scan()
	scan.load_from_file(args.file)
	for host in scan.hosts:
		for haddress in host.addresses:
			address = None
			try:
				ip = ipaddress.ip_address(haddress)
				if ip.version == 4:
					address = str(ip)
					break
			except:
				pass
		if address is None:
			address = host.addresses[0]
		
		for port in host.ports:
			if host.ports[port].state == 'open':
				tport = '%s/%s' % (port[0], port[1])
				service = 'unknown'
				if host.ports[port].service:
					service = host.ports[port].service.name
				
				
				row = TableRow(address, tport, service)
				table.append(row.to_row())
			
	print_table(table)
	