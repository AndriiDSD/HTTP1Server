#!/usr/bin/env python

# @author: Andrii Hlyvko
# Internet Technology 198:352
# Summer 2015
# Rutgers University


# A simple script that generates a web page
# for a store dynamically.

import os
import sys
from email.utils import formatdate
from datetime import datetime, timedelta
from time import mktime
from sets import Set

def writeHTML(content):
    sys.stdout.write("<html>\n<body>" + content + "</body>\n</html>")

# a simple login form
htmlForm = """
<h1>Login:</h1><br><br>
<form method="post" action="store.cgi">
  Name: <input type="text" name="fname" required><br>
<br>
  Password: <input type="password" name="fpassword" required><br>
<br>
  <input type="submit" name="Submit" value="Submit"><br>
</form>
"""

# form to display initial items in store
storeForm = """
<html>\n<body>\n
<h1> Hello {username}</h1>
<form method="post" action="store.cgi">
<select name="cars">
<option value="volvo">Volvo: price=$18000</option>
<option value="saab">Saab: price=$19000</option>
<option value="fiat">Fiat: price=$15000</option>
<option value="audi">Audi: price=$20000</option>
</select>
<input type="submit" name="addItem" value="Add To Cart"><br>
</form>\n
</body>\n</html>
"""

# get the method of http request
method= os.environ.get("REQUEST_METHOD","")


# if method was get, generate a login form
if method == "GET":
	writeHTML(htmlForm)

# if method was post, check if the user is loged in.
# if the user is loged in, generate welocme page. Else, 
# redirect to login form.
elif method == "POST":
	cookie = ""
	try:
	    cookie = os.environ.get("HTTP_COOKIE","")
	except ValueError:
	    writeHTML("Error getting cookie")
	    sys.exit()
	
	# get the name value from cookie
	# a loged in user has a name cookie set.
	crumbs=[tuple(x.split("=")) for x in cookie.split(";") ]
	userSet=False
	uname=""
	#writeHTML("crumbs %s " % crumbs)
	for t in crumbs:
	   	if t[0] == "name" or t[0]==" name":
		    uname=t[1]
		    userSet=True
	# name cookie is set
	if userSet:
	    content_length = 0
	    try:
    	        content_length = int(os.environ.get("CONTENT_LENGTH", ""))
	    except ValueError:
    		writeHTML("Invalid CONTENT_LENGTH")
    		sys.exit()

	    payload = sys.stdin.read(content_length)

	    # get cookies
	    # get items to add or remove
	    items=[tuple(x.split("=")) for x in payload.split("&") ]
	    crumbs=[tuple(x.split("=")) for x in cookie.split(";")]
	    # check action add to cart or remove from cart

	    action=0
	    for x in items:
		if(x[0]=="addItem"):
			action=1
		if(x[0]=="removeItem"):
			action=2
	    i=0

	    # cation is add to cart. Add the selected item to the cart cookie
	    if(action==1):
	        #get the items to add and add them to the set cookie
	    	t1=dict(items)

	   	if 'addItem' in t1: 
			del t1['addItem']
	    	if 'removeItem' in t1:
			del t1['removeItem']
	        list=[]	 
		for c in crumbs:
			if(c[0]==' cart' or c[0]=='cart'):
				for car in c:
					if(car!=' cart' and car!='' and car!='cart'):
						list.append(car)
		list.append(t1['cars'])
		newCookie="Set-Cookie: cart="#+t1['cars']
		x=0		
		for l in list:
			if(x<(len(list)-1)):
				newCookie=newCookie+l+"="
			else:
				newCookie=newCookie+l
			x=x+1

		sys.stdout.write(newCookie+"\r\n\r\n")
		#generate page displaying store items, user cart and total price
		stringPage="""<html><body><h1>Hello """ + uname +"""</h1><br><br>
		<form method="post" action="store.cgi">"""
		storeItems=set(['volvo','saab','fiat','audi'])
		cartItems=set(list)
		diff=storeItems-cartItems
		if(len(diff)==0):
			stringPage=stringPage+"The store is empty<br><br>"
		else:
			stringPage=stringPage+"""Store Items:<select name="cars">"""
			for c in diff:
				stringPage=stringPage+"<option value="+c+">"
				if(c=='volvo'):					
					stringPage=stringPage+"Volvo: price=$18000"
				elif(c=='saab'):
					stringPage=stringPage+"Saab: price=$19000"
				elif(c=='fiat'):
					stringPage=stringPage+"Fiat: price=$15000"
				elif(c=='audi'):
					stringPage=stringPage+"Audi: price=$20000"
				stringPAge=stringPage+"</option>"
			stringPage=stringPage+"""</select><br><br><input type="submit" name="addItem" value="Add To Cart"><br><br>"""
		
		if(len(list)==0):
			stringPage=stringPage+"Your Cart is Empty<br></form></body><html>"
		else:
			stringPage=stringPage+"""Your Cart:<select name="ucart">"""
			totalPrice=0
			for c in list:
				stringPage=stringPage+"<option value="+c+">"+c+":</option><br><br>"
				if(c=='volvo'):
					totalPrice=totalPrice+18000
				if(c=='saab'):
					totalPrice=totalPrice+19000
				if(c=='fiat'):
					totalPrice=totalPrice+15000
				if(c=='audi'):
					totalPrice=totalPrice+20000
			stringPage=stringPage+"""</select><input type="submit" name="removeItem" value="Remove From Cart"><br></form>Price:"""+str(totalPrice)+"""</body></html>"""
	   	sys.stdout.write(stringPage)

	    # the cation is remove from cart. Remove the 
	    # selected item from cart cookie
	    elif(action==2):
		# get delected ucart item and remove it from cookies
		t1=dict(items)

	   	if 'addItem' in t1: 
			del t1['addItem']
	    	if 'removeItem' in t1:
			del t1['removeItem']
	        list=[]
		for c in crumbs:
			if(c[0]==' cart' or c[0]=='cart'):
				for car in c:
					if(car!=' cart' and car!='' and car!='cart'):
						list.append(car)
		list.remove(t1['ucart'])

		newCookie="Set-Cookie: cart="
		x=0		
		for l in list:
			if(x<(len(list)-1)):
				newCookie=newCookie+l+"="
			else:
				newCookie=newCookie+l
			x=x+1

		sys.stdout.write(newCookie+"\r\n\r\n")
		stringPage="""<html><body><h1>Hello """ + uname +"""</h1><br><br>
		<form method="post" action="store.cgi">"""
		storeItems=set(['volvo','saab','fiat','audi'])
		cartItems=set(list)
		diff=storeItems-cartItems
		if(len(diff)==0):
			stringPage=stringPage+"The store is empty<br><br>"
		else:
			stringPage=stringPage+"""Store Items:<select name="cars">"""
			for c in diff:
				stringPage=stringPage+"<option value="+c+">"
				if(c=='volvo'):					
					stringPage=stringPage+"Volvo: price=$18000"
				elif(c=='saab'):
					stringPage=stringPage+"Saab: price=$19000"
				elif(c=='fiat'):
					stringPage=stringPage+"Fiat: price=$15000"
				elif(c=='audi'):
					stringPage=stringPage+"Audi: price=$20000"
				stringPAge=stringPage+"</option>"
			stringPage=stringPage+"""</select><br><br><input type="submit" name="addItem" value="Add To Cart"><br><br>"""
		if(len(list)==0):
			stringPage=stringPage+"Your Cart is Empty<br></form></body><html>"
		else:
			stringPage=stringPage+"""Your Cart:<select name="ucart">"""
			totalPrice=0
			for c in list:
				stringPage=stringPage+"<option value="+c+">"+c+":</option><br><br>"
				if(c=='volvo'):
					totalPrice=totalPrice+18000
				if(c=='saab'):
					totalPrice=totalPrice+19000
				if(c=='fiat'):
					totalPrice=totalPrice+15000
				if(c=='audi'):
					totalPrice=totalPrice+20000
			stringPage=stringPage+"""</select><input type="submit" name="removeItem" value="Remove From Cart"><br></form>Price:"""+str(totalPrice)+"""</body></html>"""
	   	sys.stdout.write(stringPage)
		
	    else:
		# the name cookie expired
		# redirect to login
		sys.stdout.write("Set-Cookie: cart=\r\n\r\n")
		writeHTML(htmlForm)

	    sys.exit()

	#cookie was not set, so set cookie with the user name and empty cart
	else:
	    #get payload from input and print it
	    content_length = 0
	    try:
    	        content_length = int(os.environ.get("CONTENT_LENGTH", ""))
	    except ValueError:
    		writeHTML("Invalid CONTENT_LENGTH")
    		sys.exit()

	    payload = sys.stdin.read(content_length)
	    l=[tuple(x.split("=")) for x in payload.split("&") ]
	    #check if have all the filds set
	    userSet=False
	    passwordSet=False
	    submitSet=False
	    upass=""
	    uname=""
	    for t in l:
	   	if t[0] == "fname":
		    uname=t[1]
		    userSet=True
		elif t[0] == "fpassword":
		    upass=t[1]
		    passwordSet=True
		elif t[0] == "Submit":
		    submitSet=True

	    if (passwordSet==False or userSet==False or submitSet==False):
		sys.stdout.write("Set-Cookie: cart=\r\n\r\n")
		writeHTML(htmlForm)
	        sys.exit()

	    nowDate=datetime.now() + timedelta(minutes=3)

	    timeStamp=mktime(nowDate.timetuple())
	    strTime=formatdate(timeval=timeStamp,localtime=True,usegmt=True)
	    strTime=strTime[:strTime.find("-")]
	    strTime=strTime+"EDT"

	    setnameCookie="Set-Cookie: name=" + uname +"; Expires="+strTime + "\r\n"
	    setCartCookie="Set-Cookie: cart=\r\n\r\n"
	    sys.stdout.write(setnameCookie+setCartCookie+storeForm.format(username=uname))

else:
	writeHTML("Invalid method")

