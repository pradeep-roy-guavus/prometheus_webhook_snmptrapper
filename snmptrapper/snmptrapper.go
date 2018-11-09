package snmptrapper

import (
	"os"
	"os/signal"
	"sync"
//        "fmt"
        "bufio"
        "strings"

	config "github.com/pradeep-roy-guavus/prometheus_webhook_snmptrapper/config"
	types "github.com/pradeep-roy-guavus/prometheus_webhook_snmptrapper/types"

	logrus "github.com/Sirupsen/logrus"
	snmpgo "github.com/k-sone/snmpgo"
)

var (
	log      = logrus.WithFields(logrus.Fields{"logger": "SNMP-trapper"})
	myConfig config.Config
	trapOIDs types.TrapOIDs
    oidMap map[string][2]string
)

func init() {
	// Set the log-level:
	logrus.SetLevel(logrus.DebugLevel)

	// Configure which OIDs to use for the SNMP Traps:
	trapOIDs.FiringTrap, _ = snmpgo.NewOid("1.3.6.1.3.1977.1.0.1")
	trapOIDs.RecoveryTrap, _ = snmpgo.NewOid("1.3.6.1.3.1977.1.0.2")
	trapOIDs.Instance, _ = snmpgo.NewOid("1.3.6.1.3.1977.1.1.1")
	trapOIDs.Service, _ = snmpgo.NewOid("1.3.6.1.3.1977.1.1.2")
	trapOIDs.Location, _ = snmpgo.NewOid("1.3.6.1.3.1977.1.1.3")
	trapOIDs.Severity, _ = snmpgo.NewOid("1.3.6.1.3.1977.1.1.4")
	trapOIDs.Description, _ = snmpgo.NewOid("1.3.6.1.3.1977.1.1.5")
	trapOIDs.JobName, _ = snmpgo.NewOid("1.3.6.1.3.1977.1.1.6")
	trapOIDs.TimeStamp, _ = snmpgo.NewOid("1.3.6.1.3.1977.1.1.7")

    //oidMap = initMap(conf.Datafile)
    //fmt.Println(oidMap)
	//log.WithFields(logrus.Fields{"filepath": conf.Datafile}).Info("Reading the data file")
}

func readLines(path string) ([]string, error) {
  file, err := os.Open(path)
  if err != nil {
    return nil, err
  }
  defer file.Close()

  var lines []string
  scanner := bufio.NewScanner(file)
  for scanner.Scan() {
    lines = append(lines, scanner.Text())
  }
  return lines, scanner.Err()
}

func parseLine(line string) []string {
  //fmt.Printf("%s\n", strings.Split(line, "^"))
  return strings.Split(line, "^")
}

func initMap(path string) map[string][2]string {
  oidMap = make(map[string][2]string)

  lines, err := readLines(path)
  if err != nil {
    log.WithFields(logrus.Fields{"trap file": path}).Info("Error reading trap config")
    //log.Fatalf("readLines: %s", err)
  } else {
    log.WithFields(logrus.Fields{"filepath": path}).Info("Reading the trap file")
    for _, line := range lines {
        //fmt.Println(line)
        tokens := parseLine(line)
        oidMap[tokens[0]] = [2]string{tokens[1], tokens[2]}
    }
  }
  return oidMap
}

func Run(myConfigFromMain config.Config, alertsChannel chan types.Alert, waitGroup *sync.WaitGroup) {

    oidMap = initMap(myConfigFromMain.Datafile)

	log.WithFields(logrus.Fields{"address": myConfigFromMain.SNMPTrapAddress}).Info("Starting the SNMP trapper")

	// Populate the config:
	myConfig = myConfigFromMain

	// Set up a channel to handle shutdown:
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Kill, os.Interrupt)

	// Handle incoming alerts:
	go func() {
		for {
			select {

			case alert := <-alertsChannel:

				// Send a trap based on this alert:
				log.WithFields(logrus.Fields{"status": alert.Status}).Debug("Received an alert")
				sendTrap(alert)
			}
		}
	}()

	// Wait for shutdown:
	for {
		select {
		case <-signals:
			log.Warn("Shutting down the SNMP trapper")

			// Tell main() that we're done:
			waitGroup.Done()
			return
		}
	}

}
