import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.net.SocketTimeoutException;
import java.net.URLDecoder;
import java.nio.file.Files;
import java.nio.file.InvalidPathException;
import java.nio.file.Path;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;
import java.util.List;
import java.util.Locale;
import java.util.StringTokenizer;
import java.util.TimeZone;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.SynchronousQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;


/**
 * 
 * @author Andrii Hlyvko
 */

public class HTTP1ServerASP implements Runnable {
	
	private Socket connected; // socked used for a connected client
	private PrintWriter connectedOut; // output stream of the socket
	private int serverPort;  // port the server in listening on
	private String serverAddr; // ip of the server
	
	private String request; // holds the method+resource+http version
	private String method; // method of request
	private String resource; // resource requested
	private String version; // http version
	private String query; // a query str attached to the end of the URL
	private String fragment; // fragment at the end of URL
	
	//request headers
	private String ifModifiedSince; // if-Modified-Since header
	private String requestType; // Content-Type header of the request
	private String requestLength; // Content-Length header of the request
	private String requestFrom;  //From header of the request
	private String requestUserAgent; //User-Agent header of the request
	private String requestCookie;
	
	//request payload ISO-8859-1 encoded
	private String clientPayload;
	
	//full client request without payload
	private String clientRequest; // the full client request
	
	
	//accepted date formats
	public static final String PATTERN_RFC1123 = "EEE, dd MMM yyyy HH:mm:ss zzz";
	public static final String PATTERN_RFC1036 = "EEEE, dd-MMM-yy HH:mm:ss zzz";
	public static final String PATTERN_ASCTIME = "EEE MMM d HH:mm:ss yyyy";
	
	// response headers
	private String DateHeader;
	private String AllowHeader;
	private String ContentEncodingHeader;
	private String ContentLengthHeader;
	private String ContentTypeHeader;
	private String ExpiresHeader;
	private String LastModifiedHeader;
	
	// date formatter
	private SimpleDateFormat dateFormatter=new SimpleDateFormat(PATTERN_RFC1123, Locale.US);
	private static final String[] formats={PATTERN_RFC1123,PATTERN_RFC1036,PATTERN_ASCTIME};
	
	
	public HTTP1ServerASP(Socket s,int p,String serverIP)
	{
		this.connected=s;
		this.serverPort=p;
		this.serverAddr=serverIP;
		try {
			this.connected.setSoTimeout(3000); //set socket timeout to 3s
		} catch (SocketException e) {
		 System.out.println("Error: Setting Socket Timeout");
		}
		connectedOut=null; // server output
		
		try {
			connectedOut =new PrintWriter(connected.getOutputStream(),true);
		} catch (IOException e) {
			System.out.println("Error: Failed to open up IO Stream on connected socket");
			return;
		}
		method=new String();
		resource=new String();
		version=new String();
		query=new String();
		fragment=new String();
		ifModifiedSince=new String();
		requestLength=new String();
		requestType=new String();
		requestFrom=new String();
		requestUserAgent=new String();
		requestCookie=new String();
		clientRequest=new String();
		clientPayload=new String();
		
		dateFormatter.setTimeZone(TimeZone.getTimeZone("GMT"));
		
		DateHeader=new String("Date: ");// initialize response headers
		AllowHeader=new String("Allow: ");
		ContentEncodingHeader=new String("Content-Encoding: identity\r\n");
		ContentLengthHeader=new String("Content-Length: ");
		ContentTypeHeader=new String("Content-Type: ");
		ExpiresHeader=new String("Expires: ");
		LastModifiedHeader=new String("Last-Modified: ");
	}
	
	public void run() {
		InputStream connectedIn=null;
		try {
			connectedIn = this.connected.getInputStream();
		} catch (IOException e1) {
			System.out.println("Error: Could not open input stream on socket.");
			sendCode(500);
			closeStreams();
			return;
		}

		int current;
		int status=0;
		try {
			while((current=connectedIn.read())!=-1)
			{
				if(current=='\r' && status==0)
				{
						status=1;
				}
				else if(current=='\n' && status==1)
				{
					status=2;
				}
				else if (current == '\r' && status == 2)
				{
					status=3;
				}
				else if(current == '\n' && status==3)
				{
					status=4;
				}
				else 
					status=0;
				this.clientRequest=this.clientRequest.concat(""+(char)current);
				
				if(status==4)
					break;
			}
		}catch(SocketTimeoutException e)
		{
			System.out.println("---------------------");
			sendCode(408);
			System.out.println("---------------------");
			closeStreams();
			return;
		}
		catch (IOException e1) {
			System.out.println("Error: Reading from socket.");
			sendCode(500);
			closeStreams();
			return;
		}  	
			
		System.out.println("----------------------------------------------");
		System.out.print("Client Request:\r\n"+this.clientRequest);
		System.out.println("Server Response:");
		
		this.parseRequest(this.clientRequest);
		
		if(request==null)
		{
			sendCode(400);
			closeStreams();
			return;
		}
		
		if(request.isEmpty())
		{
			sendCode(400);
			closeStreams();
			return;
		}
		
		//check if request had correct format
		if(this.method.isEmpty()||this.resource.isEmpty()||this.version.isEmpty())
		{
			sendCode(400);
			closeStreams();
			return;
		}
		
		// check if version starts with HTTP/
		if(!version.startsWith("HTTP/"))
		{
			sendCode(400);
			closeStreams();
			return;
		}
		
		//check http version
		double v=getVersionNumber();
		
		
		if(v>1.1)
		{
			sendCode(505);
			closeStreams();
			return;
		}
		else if(v<=0)
		{
			sendCode(400);
			closeStreams();
			return;
		}
		
		//check method implemented
		if(method.compareTo("GET")!=0 && method.compareTo("POST")!=0 && method.compareTo("HEAD")!=0)
		{
			if(method.compareTo("PUT")==0||method.compareTo("DELETE")==0||method.compareTo("TRACE")==0
					||method.compareTo("OPTIONS")==0||method.compareTo("CONNECT")==0||
					method.compareTo("PATCH")==0||method.compareTo("LINK")==0
					||method.compareTo("UNLINK")==0)
			{
			sendCode(501);
			closeStreams();
			return;
			}
			else
			{
				sendCode(400);
				closeStreams();
				return;
			}
		}
		
		// if content length header was present get the payload
		if(!this.requestLength.isEmpty())
		{
			String i=new String();
			try{
			i=this.requestLength.substring(this.requestLength.indexOf(" ")+1);
			}catch(IndexOutOfBoundsException e)
			{
				sendCode(411);
				return;
			}
			int requestBodyLength=-1;
			try{
			requestBodyLength=Integer.parseInt(i);
			}catch(NumberFormatException e)
			{
				sendCode(411);
				return;
			}
			if(requestBodyLength<0)
			{
				sendCode(411);
				return;
			}
			
			byte[] pl=new byte[requestBodyLength];
			
			try {
				connectedIn.read(pl, 0, requestBodyLength);
			} catch (IOException e) {
				sendCode(500);
				return;
			}
			try {
				this.clientPayload=new String(pl,"ISO-8859-1");
			} catch (UnsupportedEncodingException e) {
				sendCode(500);
				return;
			}
			System.out.println("Client Payload: ");
			System.out.println(this.clientPayload);
			System.out.println();
			
		}
		
		
		if(method.compareTo("GET")==0)
		{
			try{
				handleGETRequest();
			}catch(Exception e)
			{
				System.out.println(e.getMessage());
				sendCode(500);
				return;
			}
		}
		else if(method.compareTo("POST")==0)
		{
			try{
				handlePOSTRequest();
			}catch(Exception e)
			{
				System.out.println(e.getMessage());
				sendCode(500);
				return;
			}
		}
		else if(method.compareTo("HEAD")==0)
			
		{
			handleHEADRequest();
		}
		else
		{
			sendCode(501);
			closeStreams();
			return;
		}
		
		//close all streams
		closeStreams();
	}
	
	/**
	 * This method is responsible for responding to a client POST request.
	 */
	private void handlePOSTRequest()
	{
		// check content length header
		// if missing send 411
		if(this.requestLength.isEmpty())
		{
			sendCode(411);
			return;
		}
		String i=new String();
		try{
		i=this.requestLength.substring(this.requestLength.indexOf(" ")+1);
		}catch(IndexOutOfBoundsException e)
		{
			sendCode(411);
			return;
		}
		int requestBodyLength=-1;
		try{
		requestBodyLength=Integer.parseInt(i);
		}catch(NumberFormatException e)
		{
			sendCode(411);
			return;
		}
		if(requestBodyLength<0)
		{
			sendCode(411);
			return;
		}
		if(this.requestLength.lastIndexOf(" ")!=this.requestLength.indexOf(" "))
		{
			sendCode(411);//there was extra stuff after the length nuber in the header
			return;
		}
		
		//if missing content type - send 500
		if(this.requestType.isEmpty())
		{
			sendCode(500);
			return;
		}
		// accept application/x-www-form-urlencoded content type
		if(this.requestType.compareTo("Content-Type: application/x-www-form-urlencoded")!=0
				&& this.requestType.compareTo("Content-Type: multipart/form-data")!=0)
		{
			sendCode(500);
			return;
		}
		// check if resource is cgi, if not - send 405
		String path=new String();
		path=".".concat(this.resource);
		File f=null;
		try{
			f=new File(path);
		}catch(NullPointerException e)
		{
			sendCode(500);
			return;
		}
		try{
			if(f.exists())
			{
				if(f.isFile())
				{
					//check if a cgi file
					String mime=new String();
					
					String fileName = f.getName();
			        if(fileName.lastIndexOf(".") != -1 && fileName.lastIndexOf(".") != 0)
			        mime= fileName.substring(fileName.lastIndexOf(".")+1);
			        else 
			        	mime= "";
			        if(mime.compareToIgnoreCase("cgi")!=0)
			        {
			        	sendCode(405);
			        	return;
			        }
					// check for excecute permission. send 403 if not allowed
					if(!f.canExecute())
					{
						sendCode(403);// do not have read access to resource
						return;
					}
				}
				else
				{
					sendCode(404);
					return;
				}
			}
			else // resource does not exist
			{
				sendCode(404);
				return;
			}
		}catch(SecurityException e)
		{
			sendCode(403);
			return;
		}
		
		// set env vars
		List<String> envs=new ArrayList<String>();
		
		//CONTENT_LENGTH: the length of the decoded payload in bytes
		String ContentLengthEnv=new String("CONTENT_LENGTH="+this.clientPayload.length());
		envs.add(ContentLengthEnv);
		
		//SCRIPT_NAME: the path of the current CGI script. (Example: For the request "POST /cgi-bin/test.cgi HTTP/1.0", SCRIPT_NAME = /cgi-bin/test.cgi)
		String ScriptNameEnv=new String("SCRIPT_NAME="+resource);
		envs.add(ScriptNameEnv);
		
		//SERVER_NAME: the IP of the server
		String ServerNameEnv=new String("SERVER_NAME="+this.serverAddr);
		envs.add(ServerNameEnv);
		
		//SERVER_PORT: the port that the server is listening to
		String ServerPortEnv=new String("SERVER_PORT="+this.serverPort);
		envs.add(ServerPortEnv);
		
		//HTTP_FROM: if the POST request has the header "From", then set this to the value of "From"
		String FromEnv=new String();
		String UserAgentEnv=new String();
		String CookieEnv=new String();
		String RequestMethodEnv=new String("REQUEST_METHOD=POST");
		//boolean includeFrom=false,includeUserAgent=false,includeCookie=false;
		if(!this.requestFrom.isEmpty())
		{
			FromEnv="HTTP_FROM="+this.requestFrom.substring(this.requestFrom.indexOf(" ")+1);
			envs.add(FromEnv);
		}
		//HTTP_USER_AGENT: if the POST request has the header "User-Agent", then set this to the value of "User-Agent"
		if(!this.requestUserAgent.isEmpty())
		{
			UserAgentEnv="HTTP_USER_AGENT="+this.requestUserAgent.substring(this.requestUserAgent.indexOf(" ")+1);
			envs.add(UserAgentEnv);
		}
		if(!this.requestCookie.isEmpty())
		{
			CookieEnv="HTTP_COOKIE="+this.requestCookie.substring(this.requestCookie.indexOf(" ")+1);
			envs.add(CookieEnv);
		}
		envs.add(RequestMethodEnv);
		String[] envVars=envs.toArray(new String[0]);
		
		
		Runtime runtime=Runtime.getRuntime();
		Process child=null;
		
		try {//execute the script
			child=runtime.exec(f.getCanonicalPath(), envVars);
			////////////////////////////////////// read script output
			byte buffer[]=new byte[1024];
			int bytesRead=0;
			OutputStream cgiOut=null;
			connectedOut.flush();
			cgiOut=child.getOutputStream();
			
			String scriptResponse=new String();
			if(this.clientPayload.length()>0)
			{//write the payload to stdin og the script
				if(this.requestType.startsWith("Content-Type: application/x-www-form-urlencoded"))
				clientPayload=URLDecoder.decode(clientPayload,"UTF-8");
				cgiOut.write(this.clientPayload.getBytes());
				cgiOut.flush();
				cgiOut.close();
			}
			
			try {
				   	InputStream cgiIn=child.getInputStream();
				   	//read raw bytes and store them in a string while trimming the null bytes at the end
				    while ((bytesRead = cgiIn.read(buffer))>0) {
				    	String tmp=new String(buffer);
				    	tmp=tmp.trim();
				    	scriptResponse=scriptResponse.concat(tmp);
				    }
				    scriptResponse=scriptResponse.trim();
				    cgiIn.close();
				} catch (IOException x) {
					sendCode(404);
				    return;
				}
			////////////////////////////////////////////
				
				
				if(!scriptResponse.isEmpty())
				{//send script output
					sendCode(200);
					
					this.ContentTypeHeader=this.ContentTypeHeader.concat("text/html\r\n");
					System.out.print(this.ContentTypeHeader);
					this.connectedOut.print(this.ContentTypeHeader);
					this.connectedOut.flush();
					
					this.ContentLengthHeader=this.ContentLengthHeader.concat(scriptResponse.length()+"\r\n");
					System.out.print(this.ContentLengthHeader);
					this.connectedOut.print(this.ContentLengthHeader);
					this.connectedOut.flush();
					
					System.out.print(this.ContentEncodingHeader);
					this.connectedOut.print(this.ContentEncodingHeader);
					this.connectedOut.flush();
					
					if(f.canRead()&&f.canExecute())
					{
						AllowHeader=AllowHeader.concat("GET, HEAD, POST\r\n");
					}
					else if(!f.canExecute()&&f.canRead())
					{
						AllowHeader=AllowHeader.concat("GET, HEAD\r\n");
					}
					else if(f.canExecute()&&!f.canRead())
					{
						AllowHeader=AllowHeader.concat("POST\r\n");
					}
					System.out.print(this.AllowHeader);
					this.connectedOut.print(this.AllowHeader);
					this.connectedOut.flush();
					
					
					Calendar c=Calendar.getInstance();
					Date current=new Date();
					c.setTime(current);
					c.add(Calendar.DATE, 2);
					current=c.getTime();
					String futureDate=dateFormatter.format(current);
					this.ExpiresHeader=this.ExpiresHeader.concat(futureDate)+"\r\n";
					System.out.print(this.ExpiresHeader);
					this.connectedOut.print(this.ExpiresHeader);
					this.connectedOut.flush();
					
					if(!scriptResponse.startsWith("Set-Cookie: "))
					{
						this.connectedOut.print("\r\n");
						System.out.println("");
						System.out.print(scriptResponse);
						this.connectedOut.print(scriptResponse);
						this.connectedOut.flush();
					}
					else
					{
						System.out.print(scriptResponse);
						this.connectedOut.print(scriptResponse);
						this.connectedOut.flush();
					}
				}
				else
				{//script had no output
					sendCode(204);
				}
		} catch (IOException e) {
			sendCode(204);
			return;
		}
	}
	
	/**
	 * This method is user to respond to a get request
	 */
	private void handleGETRequest()
	{
		String path=new String();
		path=".".concat(this.resource);
		File f=null;
		try{
			f=new File(path);
		}catch(NullPointerException e)
		{
			sendCode(500);
			System.out.println("File path is null: "+e.getMessage());
			return;
		}
		boolean isCgi=false;
		try{
			if(f.exists())
			{
				if(f.isFile())
				{
					//check if a cgi file
					String mime=new String();
					
					String fileName = f.getName();
			        if(fileName.lastIndexOf(".") != -1 && fileName.lastIndexOf(".") != 0)
			        mime= fileName.substring(fileName.lastIndexOf(".")+1);
			        else 
			        	mime= "";
			        if(mime.compareToIgnoreCase("cgi")==0)
			        {
			        	isCgi=true;
			        }
					if(!f.canRead())
					{
						sendCode(403);// do not have read access to resource
						return;
					}
				}
				else
				{
					sendCode(404);
					return;
				}
			}
			else // resource does not exist
			{
				sendCode(404);
				return;
			}
		}catch(SecurityException e)
		{
			sendCode(403);
			return;
		}

		
		
		
		//send the file if not cgi
		if(!isCgi)
		{
			if(!this.ifModifiedSince.isEmpty())//there was an if-modified-since header
			{
				//check for if modified since
				Date ifModDate=null;

				ifModDate=parseDate(this.ifModifiedSince.substring(this.ifModifiedSince.indexOf(" ")+1));

				if(ifModDate!=null && !isCgi)
				{
					if(f.lastModified()<ifModDate.getTime())//not modified
					{
						sendCode(304);
						return;
					}
				}
			}
			
			//send date header
			this.DateHeader=this.DateHeader.concat(dateFormatter.format(new Date())+"\r\n");
			
			//print last modified
			this.LastModifiedHeader=this.LastModifiedHeader.concat(dateFormatter.format(new Date(f.lastModified())))+"\r\n";
			
			//put current time + 2 days in expires header
			Calendar c=Calendar.getInstance();
			Date current=new Date();
			c.setTime(current);
			c.add(Calendar.DATE, 2);
			current=c.getTime();
			String futureDate=dateFormatter.format(current);
			this.ExpiresHeader=this.ExpiresHeader.concat(futureDate)+"\r\n";
			
			if(f.canRead()&&f.canWrite())
			{
				AllowHeader=AllowHeader.concat("GET, HEAD, POST\r\n");
			}
			else if(f.canRead()&&!f.canWrite())
			{
				AllowHeader=AllowHeader.concat("GET, HEAD\r\n");
			}
			
			// get mime type
			String mimeType=getMIME(f);
			
			this.ContentTypeHeader=this.ContentTypeHeader.concat(mimeType)+"\r\n";
			
			//content length header
			this.ContentLengthHeader=this.ContentLengthHeader.concat(f.length()+"\r\n");
			Path p=null;
			try{
				p=f.toPath();
			}catch(InvalidPathException e)
			{
				sendCode(500);
				return;
			}
			byte buffer[]=new byte[1024];
			int count=0;
			OutputStream out=null;
			connectedOut.flush();
			try {
				out=connected.getOutputStream();
			} catch (IOException e) {
				sendCode(500);
				return;
			}
			try (InputStream in = Files.newInputStream(p);
					BufferedInputStream reader =
							new BufferedInputStream(new FileInputStream(f))) {
			    	sendCode(200);//found resource and allowed permission and was modified
			    	connectedOut.print(this.DateHeader);
			    	connectedOut.print(LastModifiedHeader);
			    	connectedOut.print(this.ExpiresHeader);
			    	connectedOut.print(AllowHeader);
			    	connectedOut.print(this.ContentTypeHeader);
			    	connectedOut.print(this.ContentEncodingHeader);
			    	connectedOut.print(this.ContentLengthHeader);
			    	//print new line
			    	connectedOut.print("\r\n");
			    	connectedOut.flush();
			    
			    	while ((count = reader.read(buffer))>0) {
			    		out.write(buffer,0,count);
			    		out.flush();
			    	}
			    
			    	reader.close();
				} catch (IOException x) {
					sendCode(404);
					return;
				}
			try {
				out.close();
			} catch (IOException e) {
				return;
			}
			System.out.print(this.DateHeader);
			System.out.print(this.LastModifiedHeader);
			System.out.print(this.ExpiresHeader);
			System.out.print(this.AllowHeader);
			System.out.print(this.ContentTypeHeader);
			System.out.print(this.ContentEncodingHeader);
			System.out.print(this.ContentLengthHeader);
			System.out.print("");
			System.out.println("-----------------------------------");
		}
		else // resource is cgi
		{
			// set env vars
			List<String> envs=new ArrayList<String>();
			
			//CONTENT_LENGTH: the length of the decoded payload in bytes
			String ContentLengthEnv=new String("CONTENT_LENGTH=0");
			envs.add(ContentLengthEnv);
			
			//SCRIPT_NAME: the path of the current CGI script. (Example: For the request "POST /cgi-bin/test.cgi HTTP/1.0", SCRIPT_NAME = /cgi-bin/test.cgi)
			String ScriptNameEnv=new String("SCRIPT_NAME="+resource);
			envs.add(ScriptNameEnv);
			
			//SERVER_NAME: the IP of the server
			String ServerNameEnv=new String("SERVER_NAME="+this.serverAddr);
			envs.add(ServerNameEnv);
			
			//SERVER_PORT: the port that the server is listening to
			String ServerPortEnv=new String("SERVER_PORT="+this.serverPort);
			envs.add(ServerPortEnv);
			
			//HTTP_FROM: if the POST request has the header "From", then set this to the value of "From"
			String FromEnv=new String();
			String UserAgentEnv=new String();
			String CookieEnv=new String();
			String RequestMethodEnv=new String("REQUEST_METHOD=GET");
			if(!this.requestFrom.isEmpty())
			{
				FromEnv="HTTP_FROM="+this.requestFrom.substring(this.requestFrom.indexOf(" ")+1);
				envs.add(FromEnv);
			}
			//HTTP_USER_AGENT: if the POST request has the header "User-Agent", then set this to the value of "User-Agent"
			if(!this.requestUserAgent.isEmpty())
			{
				UserAgentEnv="HTTP_USER_AGENT="+this.requestUserAgent.substring(this.requestUserAgent.indexOf(" ")+1);
				envs.add(UserAgentEnv);
			}
			if(!this.requestCookie.isEmpty())
			{
				CookieEnv="HTTP_COOKIE="+this.requestCookie.substring(this.requestCookie.indexOf(" ")+1);
				envs.add(CookieEnv);
			}
			envs.add(RequestMethodEnv);
			String[] envVars=envs.toArray(new String[0]);
			
			
			Runtime runtime=Runtime.getRuntime();
			Process child=null;
			
			try {//execute the script
				child=runtime.exec(f.getCanonicalPath(), envVars);
				////////////////////////////////////// read script output
				byte buffer[]=new byte[1024];
				int bytesRead=0;
				connectedOut.flush();
				
				String scriptResponse=new String();
				
				try {
					   	InputStream cgiIn=child.getInputStream();
					   	//read raw bytes and store them in a string while trimming the null bytes at the end
					    while ((bytesRead = cgiIn.read(buffer))>0) {
					    	String tmp=new String(buffer);
					    	tmp=tmp.trim();
					    	scriptResponse=scriptResponse.concat(tmp);
					    }
					    scriptResponse=scriptResponse.trim();
					    cgiIn.close();
					} catch (IOException x) {
						sendCode(404);
					    return;
					}
				////////////////////////////////////////////
					
					
					if(!scriptResponse.isEmpty())
					{//send script output
						sendCode(200);
						
						this.ContentTypeHeader=this.ContentTypeHeader.concat("text/html\r\n");
						System.out.print(this.ContentTypeHeader);
						this.connectedOut.print(this.ContentTypeHeader);
						this.connectedOut.flush();
						
						this.ContentLengthHeader=this.ContentLengthHeader.concat(scriptResponse.length()+"\r\n");
						System.out.print(this.ContentLengthHeader);
						this.connectedOut.print(this.ContentLengthHeader);
						this.connectedOut.flush();
						
						System.out.print(this.ContentEncodingHeader);
						this.connectedOut.print(this.ContentEncodingHeader);
						this.connectedOut.flush();
						
						if(f.canRead()&&f.canExecute())
						{
							AllowHeader=AllowHeader.concat("GET, HEAD, POST\r\n");
						}
						else if(!f.canExecute()&&f.canRead())
						{
							AllowHeader=AllowHeader.concat("GET, HEAD\r\n");
						}
						else if(f.canExecute()&&!f.canRead())
						{
							AllowHeader=AllowHeader.concat("POST\r\n");
						}
						System.out.print(this.AllowHeader);
						this.connectedOut.print(this.AllowHeader);
						this.connectedOut.flush();
						
						
						Calendar c=Calendar.getInstance();
						Date current=new Date();
						c.setTime(current);
						c.add(Calendar.DATE, 0);
						current=c.getTime();
						String futureDate=dateFormatter.format(current);
						this.ExpiresHeader=this.ExpiresHeader.concat(futureDate)+"\r\n";
						System.out.print(this.ExpiresHeader);
						this.connectedOut.print(this.ExpiresHeader);
						this.connectedOut.flush();
						
						if(!scriptResponse.startsWith("Set-Cookie: "))
						{
							this.connectedOut.print("\r\n");
							System.out.println("");
							System.out.print(scriptResponse);
							this.connectedOut.print(scriptResponse);
							this.connectedOut.flush();
						}
						else
						{
							System.out.print(scriptResponse);
							this.connectedOut.print(scriptResponse);
							this.connectedOut.flush();
						}
						
						System.out.println("");
					}
					else
					{//script had no output
						System.out.println("Response is empty");
						sendCode(204);
					}
			} catch (IOException e) {
				System.out.println("Error running cgi");
				sendCode(204);
				return;
			}
		}
	}
	private void handleHEADRequest()
	{
		String path=new String();
		path=".".concat(this.resource);
		File f=null;
		try{
			f=new File(path);
		}catch(NullPointerException e)
		{
			sendCode(500);
			System.out.println("File path is null: "+e.getMessage());
			return;
		}
		try{
			if(f.exists())
			{
				if(f.isFile())
				{
					if(!f.canRead())
					{
						sendCode(403);// do not have read access to resource
						return;
					}
				}
				else
				{
					sendCode(404);
					return;
				}
			}
			else // resource does not exist
			{
				sendCode(404);
				return;
			}
		}catch(SecurityException e)
		{
			sendCode(403);
			return;
		}
		
		
		//send date header
		this.DateHeader=this.DateHeader.concat(dateFormatter.format(new Date())+"\r\n");
		
		//print last modified
		this.LastModifiedHeader=this.LastModifiedHeader.concat(dateFormatter.format(new Date(f.lastModified())))+"\r\n";
		
		//put current time + 2 days in expires header
		Calendar c=Calendar.getInstance();
		Date current=new Date();
		c.setTime(current);
		c.add(Calendar.DATE, 2);
		current=c.getTime();
		String futureDate=dateFormatter.format(current);
		this.ExpiresHeader=this.ExpiresHeader.concat(futureDate)+"\r\n";
		
		if(f.canRead()&&f.canWrite())
		{
			AllowHeader=AllowHeader.concat("GET, HEAD, POST\r\n");
		}
		else if(f.canRead()&&!f.canWrite())
		{
			AllowHeader=AllowHeader.concat("GET, HEAD\r\n");
		}
		
		// get mime type
		String mimeType=getMIME(f);
		
		this.ContentTypeHeader=this.ContentTypeHeader.concat(mimeType)+"\r\n";
		
		//content length header
		this.ContentLengthHeader=this.ContentLengthHeader.concat(f.length()+"\r\n");
		
		sendCode(200);//found resource and allowed permission and was modified
	    connectedOut.print(this.DateHeader);
	    connectedOut.print(LastModifiedHeader);
	    connectedOut.print(this.ExpiresHeader);
	    connectedOut.print(AllowHeader);
	    connectedOut.print(this.ContentTypeHeader);
	    connectedOut.print(this.ContentEncodingHeader);
	    connectedOut.print(this.ContentLengthHeader);
		//print new line
		connectedOut.print("\r\n");
		connectedOut.flush();
		
		System.out.print(this.DateHeader);
		System.out.print(this.LastModifiedHeader);
		System.out.print(this.ExpiresHeader);
		System.out.print(this.AllowHeader);
		System.out.print(this.ContentTypeHeader);
		System.out.print(this.ContentEncodingHeader);
		System.out.print(this.ContentLengthHeader);
		System.out.print("");
		System.out.println("-----------------------------------");
	}
	
	/**
	 * This method returns the MIME type of a resource
	 * @param file a file on the system
	 * @return string description of the MIME type
	 */
	private String getMIME(File file)
	{
		if(file==null)
		return null;	
		
		String mime=new String();
		
		String fileName = file.getName();
        if(fileName.lastIndexOf(".") != -1 && fileName.lastIndexOf(".") != 0)
        mime= fileName.substring(fileName.lastIndexOf(".")+1);
        else 
        	mime= "";
        
        if(mime.compareTo("html")==0||mime.compareTo("htm")==0)
        {
        	mime="text/html";
        }
        else if(mime.compareTo("C")==0||mime.compareTo("cc")==0||mime.compareTo("h")==0||mime.compareTo("txt")==0)
        {
        	mime="text/plain";
        }
        else if(mime.compareTo("gif")==0)
        {
        	mime="image/gif";
        }
        else if(mime.compareTo("png")==0)
        {
        	mime="image/png";
        }
        else if(mime.compareTo("jpe")==0||mime.compareTo("jpeg")==0||mime.compareTo("jpg")==0)
        {
        	mime="image/jpeg";
        }
        else if(mime.compareTo("zip")==0)
        {
        	mime="application/zip";
        }
        else if(mime.compareTo("gz")==0||mime.compareTo("gzip")==0)
        {
        	mime="application/x-gzip";
        }
        else if(mime.compareTo("pdf")==0)
        {
        	mime="application/pdf";
        }
        else if(mime.compareTo("bin")==0)
        {
        	mime="application/octet-stream";
        }
        else
        {
        	mime="application/octet-stream";
        }
        
        return mime;
	}
	
	/**
	 * This method parses out the version number of the http request
	 * @return version number of request or -1.0 if version could not be identified
	 */
	private double getVersionNumber()
	{
		if(this.version==null)
			return -1;
		if(this.version.isEmpty())
			return -1;
		StringTokenizer tk=new StringTokenizer(this.version,"/");
		String sV=new String();
		
		// possible values HTTP, HTTP/, HTTP/1.0, HTTP////1.0, HTTP/2.0, HTTP/0.8
		if(tk.hasMoreTokens())
		{
			sV=tk.nextToken();
		}
		else
			return -1.0;
		
		if(sV.compareTo("HTTP")!=0)
			return -1.0;
		
		if(tk.hasMoreTokens())
		{
			sV=tk.nextToken();
		}
		else
			return -1.0;
		
		double v;
		try{
			v=Double.parseDouble(sV);
		}catch(Exception e)
		{
			return -1.0;
		}
		return v;
	}
	
	/**
	 * This method sends a http message to the client using a code
	 * @param code the code of the response
	 */
	private void sendCode(int code)
	{
		if(this.connectedOut==null)
			return;
		
		switch(code){
		case 200:
			System.out.print("HTTP/1.0 200 OK\r\n");
			connectedOut.print("HTTP/1.0 200 OK\r\n");
			connectedOut.flush(); 
			break;
		case 204:
			System.out.print("HTTP/1.0 204 No Content\r\n");
			connectedOut.print("HTTP/1.0 204 No Content\r\n");
			connectedOut.flush(); 
			break;
		case 304:
			System.out.print("HTTP/1.0 304 Not Modified\r\n");
			connectedOut.print("HTTP/1.0 304 Not Modified\r\n");
			
			Calendar c=Calendar.getInstance();
			Date current=new Date();
			c.setTime(current);
			c.add(Calendar.DATE, 2);
			current=c.getTime();
			String currentDate=dateFormatter.format(current);
			connectedOut.print("Expires: "+currentDate+"\r\n\r\n");
			connectedOut.flush();
			break;
		case 400:
			System.out.print("HTTP/1.0 400 Bad Request\r\n\r\n");
			connectedOut.print("HTTP/1.0 400 Bad Request\r\n\r\n");
			connectedOut.flush();
			break;
		case 403:
			System.out.print("HTTP/1.0 403 Forbidden\r\n\r\n");
			connectedOut.print("HTTP/1.0 403 Forbidden\r\n\r\n");
			connectedOut.flush();
			break;
		case 404:
			System.out.print("HTTP/1.0 404 Not Found\r\n\r\n");
			connectedOut.print("HTTP/1.0 404 Not Found\r\n\r\n");
			connectedOut.flush();
			break;
		case 405:
			System.out.print("HTTP/1.0 405 Method Not Allowed\r\n\r\n");
			connectedOut.print("HTTP/1.0 405 Method Not Allowed\r\n\r\n");
			connectedOut.flush();
			break;
		case 408:
			System.out.print("HTTP/1.0 408 Request Timeout\r\n\r\n");
			connectedOut.print("HTTP/1.0 408 Request Timeout\r\n\r\n");
			connectedOut.flush();
			break;
		case 411:
			System.out.print("HTTP/1.0 411 Length Required\r\n\r\n");
			connectedOut.print("HTTP/1.0 411 Length Required\r\n\r\n");
			connectedOut.flush();
			break;
		case 500:
			System.out.print("HTTP/1.0 500 Internal Server Error\r\n\r\n");
			connectedOut.print("HTTP/1.0 500 Internal Server Error\r\n\r\n");
			connectedOut.flush();
			break;
		case 501:
			System.out.print("HTTP/1.0 501 Not Implemented\r\n\r\n");
			connectedOut.print("HTTP/1.0 501 Not Implemented\r\n\r\n");
			connectedOut.flush();
			break;
		case 503:
			System.out.print("HTTP/1.0 503 Service Unavailable\r\n\r\n");
			connectedOut.print("HTTP/1.0 503 Service Unavailable\r\n\r\n");
			connectedOut.flush();
			break;
		case 505:
			System.out.print("HTTP/1.0 505 HTTP Version Not Supported\r\n\r\n");
			connectedOut.print("HTTP/1.0 505 HTTP Version Not Supported\r\n\r\n");
			connectedOut.flush();
			break;
		}
	}
	
	/**
	 * This method parses out client request and fills out the method, resorce, and http version.
	 * @param r the client request
	 */
	private void parseRequest(String r)
	{
		if(r==null)
			return;
		if(r.isEmpty())
			return;
		
		StringTokenizer tk0= new StringTokenizer(r,"\r\n");
		String tmp=new String();
		
		// get the method, resource, httpversion
		if(tk0.hasMoreTokens())
		{
			this.request=tk0.nextToken();
		}
		else // no request
			return;
		
		while(tk0.hasMoreTokens())
		{
			tmp=tk0.nextToken(); //next header 
			
			if(tmp.startsWith("If-Modified-Since: "))
			{
				this.ifModifiedSince=tmp;
			}
			else if(tmp.startsWith("Content-Length: "))
			{
				this.requestLength=tmp;
			}
			else if(tmp.startsWith("Content-Type: "))
			{
				this.requestType=tmp;
			}
			else if(tmp.startsWith("From: "))
			{
				this.requestFrom=tmp;
			}
			else if(tmp.startsWith("User-Agent: "))
			{
				this.requestUserAgent=tmp;
			}
			else if(tmp.startsWith("Cookie: "))
			{
				this.requestCookie=tmp;
			}
			
		}
		
		
		
		StringTokenizer tk=new StringTokenizer(this.request," ",true);
		
		
		if(tk.hasMoreTokens())
		{
			tmp=tk.nextToken();
		}
		else
			return;
		if(tmp.compareTo(" ")==0)//cannot be another space
			return;
		
		this.method=tmp;
		
		if(tk.hasMoreTokens())//get the space
		{
			tmp=tk.nextToken();
		}
		else
			return;
		if(tmp.compareTo(" ")!=0)//next char is space
			return;
		
		
		if(tk.hasMoreTokens())//get the resource
		{
			tmp=tk.nextToken();
		}
		else
			return;
		if(tmp.compareTo(" ")==0)//cannot be another space
			return;

		this.resource=tmp;
		
		//check if resource contains a query and fragment
		if(this.resource.contains("?"))
		{
			String t=new String();
			t=this.resource;
			try{
				
			
			this.resource=this.resource.substring(0, this.resource.indexOf("?"));
			}catch(IndexOutOfBoundsException e)
			{
				this.resource="";
			}
			if(t.contains("#"))
			{
				try{
				this.query=t.substring(t.indexOf("?")+1, t.indexOf("#"));
				this.fragment=t.substring(t.indexOf("#")+1);
				}catch(IndexOutOfBoundsException e)
				{
					this.query="";
					this.fragment="";
				}
			}
			else
			{
				try{
				this.query=t.substring(t.indexOf("?")+1);
				}catch(IndexOutOfBoundsException e)
				{
					this.query="";
				}
			}
		}
		
		//get one space
		if(tk.hasMoreTokens())//get the space
		{
			tmp=tk.nextToken();
		}
		else
			return;
		if(tmp.compareTo(" ")!=0)//next char is space
			return;
		
		//get the http version
		if(tk.hasMoreTokens())//get the http version
		{
			tmp=tk.nextToken();
		}
		else
			return;
		
		if(tmp.compareTo(" ")==0)//cannot be another space
			return;
		
		//check if there is extra stuff at the end
		//and if so set the http method to empty string to end request
		this.version=tmp;
		if(tk.hasMoreTokens())
		{
			this.method="";
		}	
	}
	
	/**
	 * This method parses a string as a Date using the 3 valid HTTP date formats
	 * @param strDate the Date representation of the string
	 * @return the Date representation of the string or null if the string could not be parsed
	 */
	private Date parseDate(String strDate)
	{
		Date date=null;
		SimpleDateFormat simpleFormat;
		
		for(String format : formats)
		{
			simpleFormat = new SimpleDateFormat(format, Locale.US);
            simpleFormat.setTimeZone(TimeZone.getTimeZone("GMT"));
            
            try {
				date=simpleFormat.parse(strDate);
			} catch (ParseException e) {
				continue;
			}
		}
		
		return date;
	}
	/**
	 * This method closes the IO streams on the client socket and the socket.
	 */
	private void closeStreams()
	{
		
		try {// wait half a second before closing connection and IO streams
			connectedOut.flush();
			Thread.sleep(500);
		} catch (InterruptedException e1) {
			System.out.println("Error: thread sleep");
		} 
		connectedOut.close();
		//connectedIn.close();
		try{
			connected.close();
		}catch(IOException e)
		{
			System.out.println("Error: Closing Socket");
			return;
		}
	}

	/**
	 * The main method initializes the server to wait for client connections on a specified port. When a client 
	 * connects a thread is created that handles each request. A max of 50 connections can be established simultaneously. 
	 * If the client does not send a request within 3sec the connection will timeout.
	 * @param args
	 */
	public static void main(String[] args) {
		if(args.length!=1) // check if the number of arguments is 1
		{
			System.out.println("Error: Input the port number as the only argument");
			return;
		}
		
		//get the port number
		int port=-1;
		try{
		port= Integer.parseInt(args[0]);
		}catch(NumberFormatException e){
			System.out.println("Error: Port number must be an integer.");
			return;
		}
		
		//check the range of port number
		if(port<=1024||port>65536)
		{
			System.out.println("Error: Port number is out of range.");
			return;
		}
		
		ServerSocket serverSocket =null; //server socket
		try {
			serverSocket =new ServerSocket(port);
		} catch (IOException e) {
			System.out.println("Error: Failed to create server socket.");
			return;
		}
		
		
		ExecutorService executor=new ThreadPoolExecutor(5, 50, 10, TimeUnit.SECONDS, new SynchronousQueue<Runnable>());
		
		while(true)
		{
			Socket connectedSocket=null;
			try {
				 connectedSocket=serverSocket.accept();
			} catch (IOException e) {
				System.out.println("Error: Could not accept connection.");
				return;
			}
			
			//create new thread and pass the connected socket to it to handle the request
			try{
				executor.execute(new HTTP1ServerASP(connectedSocket,serverSocket.getLocalPort(),serverSocket.getInetAddress().getHostAddress()));
			}catch(RejectedExecutionException e){
				PrintWriter out=null; // server output
				
				try {
					out =new PrintWriter(connectedSocket.getOutputStream(),true);
				} catch (IOException m) {
					System.out.println("Error: Failed to open up IO Stream on connected socket");
					return;
				}
				out.print("503 Service Unavailable\r\n\r\n");
				out.flush();
				
				out.close();
				try {
					connectedSocket.close();
				} catch (IOException e1) {
					System.out.println("Failed to close client socket");
					return;
				}
			}
		}
	}
}
