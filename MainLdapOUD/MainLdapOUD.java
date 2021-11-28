import java.io.PrintStream;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Hashtable;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.BasicAttribute;
import javax.naming.directory.BasicAttributes;
import javax.naming.directory.InitialDirContext;
import javax.naming.ldap.LdapContext;

public class MainLdap
{
  private static String paramHOSTNAME = “HOSTNAME”;
  private static String paramPORT = “PORT”;
  private static String paramBASEDN = “BASEDN”;
  private static String paramMANAGER = “MANAGER”;
  private static String paramPASSWORD = “PASSWORD”;
  private static String paramPREFISSOUSER = “PREFISSOUSER”;
  private static String paramDOMINIOMAIL = “DOMINIOMAIL”;
  private static String paramOBJECTCLASS = “OBJECTCLASS”;
  private static String paramPASSWORDATTR = “PASSWORDATTR”;
  private HashSet<String> pluginParamsName = new HashSet();
  private static Logger logger = Logger.getLogger(“UNISALUTEPROV.CUSTOM.OAM”);
  HashMap<String, String> pluginParamsValue = new HashMap();
  private HashSet<String> mandatoryPluginParamsName = new HashSet();
  private static final String CLASS_NAME = MainLdap.class.getSimpleName();
  private String decode(String pass)
  {
    logger.logp(Level.FINEST, CLASS_NAME, “decode ritorno”, pass);
    return pass;
  }
  private String calcola_user_password(String username)
  {
    String pass = “Admin2014";
    logger.logp(Level.FINEST, CLASS_NAME, “calcola_user_password ritorno”, pass);
    return pass;
  }
  public String getDescription()
  {
    return CLASS_NAME;
  }
  public String getPluginName()
  {
    return CLASS_NAME;
  }
  public int getRevision()
  {
    return 0;
  }
  public boolean getMonitoringStatus()
  {
    return false;
  }
  public int process(String hostname, String port, String manager, String password, String basedn)
  {
    String methodName = “process”;
    String userName = “dummyuser”;
    logger.logp(Level.FINEST, CLASS_NAME, methodName, “refreshing plugin configuration parameter from step configuration”);
    String prefissouser = “ext”;
    String dominiomail = “unisalute.esterni.it”;
    String passwordattr = “userpassword”;
    LdapContext esito_lookup = null;
    String cnValue = prefissouser + userName;
    String dnUser = “cn=” + cnValue + “,” + basedn;
    logger.logp(Level.FINEST, CLASS_NAME, methodName, “format dnuser ” + dnUser);
    String user_password = calcola_user_password(cnValue);
    try
    {
      String decode_password = decode(password);
      Hashtable<String, Object> env = new Hashtable();
      env.put(“java.naming.factory.initial”, “com.sun.jndi.ldap.LdapCtxFactory”);
      env.put(“java.naming.provider.url”, “ldap://” + hostname + “:” + port);
      env.put(“java.naming.security.authentication”, “simple”);
      env.put(“java.naming.security.principal”, manager);
      env.put(“java.naming.security.credentials”, decode_password);
      logger.logp(Level.FINEST, CLASS_NAME, methodName, “provider url:ldap://” + hostname + “:” + port);
      logger.logp(Level.FINEST, CLASS_NAME, methodName, “Prima Initial Context”);
      InitialDirContext ctx = new InitialDirContext(env);
      logger.logp(Level.FINEST, CLASS_NAME, methodName, “Dopo Initial Context - connected; cerco utente=” + dnUser);
      try
      {
        esito_lookup = (LdapContext)ctx.lookup(dnUser);
      }
      catch (Exception e)
      {
        System.out.println(“eccezione” + e);
      }
      logger.logp(Level.FINEST, CLASS_NAME, methodName, ” dopo lookup”);
      if (esito_lookup != null)
      {
        System.out.println(“sono esito lookup” + esito_lookup.toString());
        return 0;
      }
      logger.logp(Level.FINEST, CLASS_NAME, methodName, “utente=” + dnUser + ” non esiste; lo creo!!“);
      
      Attribute classes = new BasicAttribute(“objectclass”);
      BasicAttributes attrs = new BasicAttributes();
      classes.add(“top”);
      classes.add(“person”);
      classes.add(“inetOrgPerson”);
      classes.add(“orclUser”);
      classes.add(“orclUserV2");
      classes.add(“orclIDXPerson”);
      classes.add(“oblixPersonPwdPolicy”);
      classes.add(“oblixorgperson”);
      attrs.put(classes);
      attrs.put(“cn”, cnValue);
      attrs.put(“uid”, cnValue);
      attrs.put(“sn”, cnValue);
      attrs.put(passwordattr, user_password);
      logger.logp(Level.FINEST, CLASS_NAME, methodName, “utente=” + dnUser + ”attivo la create con createSubcontext!!“);
      ctx.createSubcontext(dnUser, attrs);
    }
    catch (NamingException ne)
    {
      System.out.println(“Eccezione” + ne);
      logger.logp(Level.FINEST, CLASS_NAME, methodName, “eccezione bind o search: ” + ne);
      return 1;
    }
    BasicAttributes attrs;
    Attribute classes;
    InitialDirContext ctx;
    String decode_password;
    return 0;
  }

  public static void main(String[] args)
  {
    MainLdap temp = new MainLdap();
    System.out.println(args[0]);
    System.out.println(args[1]);
    System.out.println(args[2]);
    System.out.println(args[3]);
    System.out.println(args[4]);
    System.out.println(“esito” + temp.process(args[0], args[1], args[2], args[3], args[4]));
  }
}