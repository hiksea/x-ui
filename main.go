package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"

	"errors"
//	"flag"
	"io/ioutil"
	"net/http"
	"strings"
	"time"
	"syscall"
	_ "unsafe"
	"x-ui/config"
	"x-ui/database"
	"x-ui/logger"
	"x-ui/v2ui"
	"x-ui/web"
	"x-ui/web/global"
	"x-ui/web/service"

	"github.com/cloudflare/cloudflare-go"
	"github.com/joho/godotenv"
	"github.com/op/go-logging"
)

var OLD_IP string
var DOMAIN string
var CF_API_KEY string
var CF_API_EMAIL string
var SUBDOMAIN string

// Start CloudFlare

func updateCfSetting(cfDomain string, cfEmail string, cfGlobalAPI string, cfZoneID string, cfRunTime string) {
	err := database.InitDB(config.GetDBPath())
	if err != nil {
		fmt.Println(err)
		return
	}

	settingService := service.SettingService{}

	if cfDomain != "" {
		err := settingService.SetCfDomain(cfDomain)
		if err != nil {
			fmt.Println(err)
			return
		} else {
			logger.Info("updateCfSetting cfDomain success")
		}
	}

	if cfEmail != "" {
		err := settingService.SetCfEmail(cfEmail)
		if err != nil {
			fmt.Println(err)
			return
		} else {
			logger.Infof("updateCfSetting CfEmail success")
		}
	}

	if cfGlobalAPI != "" {
		err := settingService.SetCfGlobalAPI(cfGlobalAPI)
		if err != nil {
			fmt.Println(err)
			return
		} else {
			logger.Info("updateCfSetting cfGlobalAPI success")
		}
	}

	if cfZoneID != "" {
                err := settingService.SetCfZoneID(cfZoneID)
                if err != nil {
                        fmt.Println(err)
                        return
                } else {
                        logger.Info("updateCfSetting cfZoneID success")
                }
        }

	if cfRunTime != "" {
		err := settingService.SetCfRuntime(cfRuntime)
		if err != nil {
			fmt.Println(err)
			return
		} else {
			logger.Infof("updateCfSetting cfRuntime[%s] success", cfRuntime)
		}
	}
}

func argParse() error {
	configfile := flag.String("config", "", "Absolute path to the config env file")
	flag.Parse()

	if *configfile != "" {
		// Load dotenv file into environment, overriding existing vars
		err := godotenv.Load(*configfile)
		if err != nil {
			log.Fatal("Error loading .env file")
		}
	}

	// Get vars from environment
	DOMAIN = os.Getenv("DOMAIN")
	if DOMAIN == "" {
		msg := fmt.Sprintf("Need to define DOMAIN var")
		return errors.New(msg)
	}
	CF_API_KEY = os.Getenv("CF_API_KEY")
	if CF_API_KEY == "" {
		msg := fmt.Sprintf("Need to define CF_API_KEY var")
		return errors.New(msg)
	}
	CF_API_EMAIL = os.Getenv("CF_API_EMAIL")
	if CF_API_EMAIL == "" {
		msg := fmt.Sprintf("Need to define CF_API_EMAIL var")
		return errors.New(msg)
	}
	SUBDOMAIN = os.Getenv("SUBDOMAIN")
	if SUBDOMAIN == "" {
		msg := fmt.Sprintf("Need to define SUBDOMAIN var")
		return errors.New(msg)
	}

	return nil
}

func checkIP() {
	log.Printf("Checking IP...\n")
	new_ip := getMyIP(4)
	if OLD_IP == "" {
		// First Run
		dynDNS(new_ip)
	} else if OLD_IP != new_ip {
		log.Printf("IP Address Changed: %s -> %s", OLD_IP, new_ip)
		dynDNS(new_ip)
	}
	OLD_IP = new_ip
}

func dynDNS(ip string) {
	// Construct a new API object
	api, err := cloudflare.New(CF_API_KEY, CF_API_EMAIL)
	if err != nil {
		log.Fatal(err)

	}

	// Fetch the zone ID
	zoneID, err := api.ZoneIDByName(DOMAIN) // Assuming example.com exists in your Cloudflare account already
	if err != nil {
		log.Fatal(err)
		return
	}

	// Record to create
	newRecord := cloudflare.DNSRecord{
		Type:    "A",
		Name:    SUBDOMAIN + "." + DOMAIN,
		Content: getMyIP(4),
	}

	updateRecord(zoneID, api, &newRecord)
	log.Println("Set DNSRecord:", newRecord.Name, newRecord.Content, "\n")

	// Print records
	//showCurrentRecords(zoneID, api)
}

func updateRecord(zoneID string, api *cloudflare.API, newRecord *cloudflare.DNSRecord) {
	// Get current records
	//log.Println("Getting old dns records... ")
	dns := cloudflare.DNSRecord{Type: newRecord.Type, Name: newRecord.Name}
	old_records, err := api.DNSRecords(zoneID, dns)
	if err != nil {
		log.Fatal(err)
		return
	}

	if len(old_records) == 1 {
		// Update
		err := api.UpdateDNSRecord(zoneID, old_records[0].ID, *newRecord)
		if err != nil {
			log.Fatal(err)
			return
		}
		return
	}

	if len(old_records) > 1 {
		// Delete every record
		for _, record := range old_records {
			err := api.DeleteDNSRecord(zoneID, record.ID)
			if err != nil {
				log.Fatal(err)
				return
			}
			msg := fmt.Sprintf("Deleted DNSRecord: %s - %s: %s", record.Type, record.Name, record.Content)
			log.Println(msg)
		}
	}

	// Create if < 1 or > 1
	_, err = api.CreateDNSRecord(zoneID, *newRecord)
	if err != nil {
		log.Fatal(err)
		return
	}
	//log.Println("Done")
}

func showCurrentRecords(zoneID string, api *cloudflare.API) {
	// Fetch all DNS records for example.org
	records, err := api.DNSRecords(zoneID, cloudflare.DNSRecord{})
	if err != nil {
		log.Println(err)
		return
	}

	for _, r := range records {
		msg := fmt.Sprintf("%s: %s", r.Name, r.Content)
		log.Println(msg)
	}
}

func getMyIP(protocol int) string {
	var target string
	if protocol == 4 {
		target = "http://myexternalip.com/raw"
	} else {
		return ""

	}
	resp, err := http.Get(target)
	if err == nil {
		contents, err := ioutil.ReadAll(resp.Body)
		if err == nil {
			defer resp.Body.Close()
			return strings.TrimSpace(string(contents))

		}

	}
	return ""
}

// End CloudFlare

func runWebServer() {
	log.Printf("%v %v", config.GetName(), config.GetVersion())

	switch config.GetLogLevel() {
	case config.Debug:
		logger.InitLogger(logging.DEBUG)
	case config.Info:
		logger.InitLogger(logging.INFO)
	case config.Warn:
		logger.InitLogger(logging.WARNING)
	case config.Error:
		logger.InitLogger(logging.ERROR)
	default:
		log.Fatal("unknown log level:", config.GetLogLevel())
	}

	err := database.InitDB(config.GetDBPath())
	if err != nil {
		log.Fatal(err)
	}

	var server *web.Server

	server = web.NewServer()
	global.SetWebServer(server)
	err = server.Start()
	if err != nil {
		log.Println(err)
		return
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGHUP, syscall.SIGTERM, syscall.SIGKILL)
	for {
		sig := <-sigCh

		switch sig {
		case syscall.SIGHUP:
			err := server.Stop()
			if err != nil {
				logger.Warning("stop server err:", err)
			}
			server = web.NewServer()
			global.SetWebServer(server)
			err = server.Start()
			if err != nil {
				log.Println(err)
				return
			}
		default:
			server.Stop()
			return
		}
	}
}

func resetSetting() {
	err := database.InitDB(config.GetDBPath())
	if err != nil {
		fmt.Println(err)
		return
	}

	settingService := service.SettingService{}
	err = settingService.ResetSettings()
	if err != nil {
		fmt.Println("reset setting failed:", err)
	} else {
		fmt.Println("reset setting success")
	}
}

func showSetting(show bool) {
	if show {
		settingService := service.SettingService{}
		port, err := settingService.GetPort()
		if err != nil {
			fmt.Println("get current port fialed,error info:", err)
		}
		userService := service.UserService{}
		userModel, err := userService.GetFirstUser()
		if err != nil {
			fmt.Println("get current user info failed,error info:", err)
		}
		username := userModel.Username
		userpasswd := userModel.Password
		if (username == "") || (userpasswd == "") {
			fmt.Println("current username or password is empty")
		}
		fmt.Println("current pannel settings as follows:")
		fmt.Println("username:", username)
		fmt.Println("userpasswd:", userpasswd)
		fmt.Println("port:", port)
	}
}

func updateTgbotEnableSts(status bool) {
	settingService := service.SettingService{}
	currentTgSts, err := settingService.GetTgbotenabled()
	if err != nil {
		fmt.Println(err)
		return
	}
	logger.Infof("current enabletgbot status[%v],need update to status[%v]", currentTgSts, status)
	if currentTgSts != status {
		err := settingService.SetTgbotenabled(status)
		if err != nil {
			fmt.Println(err)
			return
		} else {
			logger.Infof("SetTgbotenabled[%v] success", status)
		}
	}
	return
}

func updateTgbotSetting(tgBotToken string, tgBotChatid int, tgBotRuntime string) {
	err := database.InitDB(config.GetDBPath())
	if err != nil {
		fmt.Println(err)
		return
	}

	settingService := service.SettingService{}

	if tgBotToken != "" {
		err := settingService.SetTgBotToken(tgBotToken)
		if err != nil {
			fmt.Println(err)
			return
		} else {
			logger.Info("updateTgbotSetting tgBotToken success")
		}
	}

	if tgBotRuntime != "" {
		err := settingService.SetTgbotRuntime(tgBotRuntime)
		if err != nil {
			fmt.Println(err)
			return
		} else {
			logger.Infof("updateTgbotSetting tgBotRuntime[%s] success", tgBotRuntime)
		}
	}

	if tgBotChatid != 0 {
		err := settingService.SetTgBotChatId(tgBotChatid)
		if err != nil {
			fmt.Println(err)
			return
		} else {
			logger.Info("updateTgbotSetting tgBotChatid success")
		}
	}
}

func updateSetting(port int, username string, password string) {
	err := database.InitDB(config.GetDBPath())
	if err != nil {
		fmt.Println(err)
		return
	}

	settingService := service.SettingService{}

	if port > 0 {
		err := settingService.SetPort(port)
		if err != nil {
			fmt.Println("set port failed:", err)
		} else {
			fmt.Printf("set port %v success", port)
		}
	}
	if username != "" || password != "" {
		userService := service.UserService{}
		err := userService.UpdateFirstUser(username, password)
		if err != nil {
			fmt.Println("set username and password failed:", err)
		} else {
			fmt.Println("set username and password success")
		}
	}
}

func main() {
	err := argParse()
	if err != nil {
		log.Fatal(err)
	}

	log.SetOutput(os.Stdout)

	//OLD_IP = getMyIP(4)
	//dynDNS(OLD_IP)
	checkIP()

	log.Println("Entering Control Loop... ")
	for {
		time.Sleep(60 * time.Second)
		go checkIP()
	}

	if len(os.Args) < 2 {
		runWebServer()
		return
	}

	var showVersion bool
	flag.BoolVar(&showVersion, "v", false, "show version")

	runCmd := flag.NewFlagSet("run", flag.ExitOnError)

	v2uiCmd := flag.NewFlagSet("v2-ui", flag.ExitOnError)
	var dbPath string
	v2uiCmd.StringVar(&dbPath, "db", "/etc/v2-ui/v2-ui.db", "set v2-ui db file path")

	settingCmd := flag.NewFlagSet("setting", flag.ExitOnError)
	var port int
	var username string
	var password string
	var tgbottoken string
	var tgbotchatid int
	var enabletgbot bool
	var tgbotRuntime string
	var reset bool
	var show bool
	settingCmd.BoolVar(&reset, "reset", false, "reset all settings")
	settingCmd.BoolVar(&show, "show", false, "show current settings")
	settingCmd.IntVar(&port, "port", 0, "set panel port")
	settingCmd.StringVar(&username, "username", "", "set login username")
	settingCmd.StringVar(&password, "password", "", "set login password")
	settingCmd.StringVar(&tgbottoken, "tgbottoken", "", "set telegrame bot token")
	settingCmd.StringVar(&tgbotRuntime, "tgbotRuntime", "", "set telegrame bot cron time")
	settingCmd.IntVar(&tgbotchatid, "tgbotchatid", 0, "set telegrame bot chat id")
	settingCmd.BoolVar(&enabletgbot, "enabletgbot", false, "enable telegram bot notify")

	oldUsage := flag.Usage
	flag.Usage = func() {
		oldUsage()
		fmt.Println()
		fmt.Println("Commands:")
		fmt.Println("    run            run web panel")
		fmt.Println("    v2-ui          migrate form v2-ui")
		fmt.Println("    setting        set settings")
	}

	flag.Parse()
	if showVersion {
		fmt.Println(config.GetVersion())
		return
	}

	switch os.Args[1] {
	case "run":
		err := runCmd.Parse(os.Args[2:])
		if err != nil {
			fmt.Println(err)
			return
		}
		runWebServer()
	case "v2-ui":
		err := v2uiCmd.Parse(os.Args[2:])
		if err != nil {
			fmt.Println(err)
			return
		}
		err = v2ui.MigrateFromV2UI(dbPath)
		if err != nil {
			fmt.Println("migrate from v2-ui failed:", err)
		}
	case "setting":
		err := settingCmd.Parse(os.Args[2:])
		if err != nil {
			fmt.Println(err)
			return
		}
		if reset {
			resetSetting()
		} else {
			updateSetting(port, username, password)
		}
		if show {
			showSetting(show)
		}
		updateTgbotEnableSts(enabletgbot)
		if (tgbottoken != "") || (tgbotchatid != 0) || (tgbotRuntime != "") {
			updateTgbotSetting(tgbottoken, tgbotchatid, tgbotRuntime)
		}
	default:
		fmt.Println("except 'run' or 'v2-ui' or 'setting' subcommands")
		fmt.Println()
		runCmd.Usage()
		fmt.Println()
		v2uiCmd.Usage()
		fmt.Println()
		settingCmd.Usage()
	}
}
