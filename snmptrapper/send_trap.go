package snmptrapper

import (
	"time"
        "strings"

	types "github.com/pradeep-roy-guavus/prometheus_webhook_snmptrapper/types"

	logrus "github.com/Sirupsen/logrus"
	snmpgo "github.com/k-sone/snmpgo"
)


func addLabels(desc string, labels map[string]string) string {
    s := desc

    for key, value := range labels {
        s += (" ; " + key + " : " + value)
    }
    return s
}

func getTrapOID(status string, descr string) *snmpgo.Oid {
    var v [2]string
    var ok bool = false
    result := trapOIDs.FiringTrap
    index := 0

    if status != "firing" {
        index = 1
    } else {
        result = trapOIDs.RecoveryTrap
    }

    //log.WithFields(logrus.Fields{"oid table": oidMap}).Info("Searching")
    for key, value := range oidMap {
        if strings.HasPrefix(descr, key) {
            v = value
            ok = true
            break
        }
        //log.WithFields(logrus.Fields{"key": key, "value": value}).Info("Searching")
    }
    if ok {
        result, _  = snmpgo.NewOid(v[index])
    }

    log.WithFields(logrus.Fields{"result": result}).Info("OID lookup")
    return result
}

func sendTrap(alert types.Alert) {

	// Prepare an SNMP handler:
	snmp, err := snmpgo.NewSNMP(snmpgo.SNMPArguments{
		Version:   snmpgo.V2c,
		Address:   myConfig.SNMPTrapAddress,
		Retries:   myConfig.SNMPRetries,
		Community: myConfig.SNMPCommunity,
	})
	if err != nil {
		log.WithFields(logrus.Fields{"error": err}).Error("Failed to create snmpgo.SNMP object")
		return
	} else {
		log.WithFields(logrus.Fields{"address": myConfig.SNMPTrapAddress, "retries": myConfig.SNMPRetries, "community": myConfig.SNMPCommunity}).Debug("Created snmpgo.SNMP object")
	}

	// Build VarBind list:
	var varBinds snmpgo.VarBinds
        var desc string

	// The "enterprise OID" for the trap (rising/firing or falling/recovery):
	if alert.Status == "firing" {
		//varBinds = append(varBinds, snmpgo.NewVarBind(snmpgo.OidSnmpTrap, trapOIDs.FiringTrap))
                varBinds = append(varBinds, snmpgo.NewVarBind(snmpgo.OidSnmpTrap, getTrapOID("firing", alert.Annotations["description"])))
		varBinds = append(varBinds, snmpgo.NewVarBind(trapOIDs.TimeStamp, snmpgo.NewOctetString([]byte(alert.StartsAt.Format(time.RFC3339)))))
	} else {
		//varBinds = append(varBinds, snmpgo.NewVarBind(snmpgo.OidSnmpTrap, trapOIDs.RecoveryTrap))
                varBinds = append(varBinds, snmpgo.NewVarBind(snmpgo.OidSnmpTrap, getTrapOID("recovery", alert.Annotations["description"])))
		varBinds = append(varBinds, snmpgo.NewVarBind(trapOIDs.TimeStamp, snmpgo.NewOctetString([]byte(alert.EndsAt.Format(time.RFC3339)))))
	}

        desc = addLabels(alert.Annotations["description"], alert.Labels)

	// Insert the AlertManager variables:
	varBinds = append(varBinds, snmpgo.NewVarBind(trapOIDs.Description, snmpgo.NewOctetString([]byte(desc))))
	varBinds = append(varBinds, snmpgo.NewVarBind(trapOIDs.Instance, snmpgo.NewOctetString([]byte(alert.Labels["instance"]))))
	varBinds = append(varBinds, snmpgo.NewVarBind(trapOIDs.Severity, snmpgo.NewOctetString([]byte(alert.Labels["severity"]))))
	varBinds = append(varBinds, snmpgo.NewVarBind(trapOIDs.Location, snmpgo.NewOctetString([]byte(alert.Labels["location"]))))
	varBinds = append(varBinds, snmpgo.NewVarBind(trapOIDs.Service, snmpgo.NewOctetString([]byte(alert.Labels["service"]))))
	varBinds = append(varBinds, snmpgo.NewVarBind(trapOIDs.JobName, snmpgo.NewOctetString([]byte(alert.Labels["job"]))))

	// Create an SNMP "connection":
	if err = snmp.Open(); err != nil {
		log.WithFields(logrus.Fields{"error": err}).Error("Failed to open SNMP connection")
		return
	}
	defer snmp.Close()

	// Send the trap:
	if err = snmp.V2Trap(varBinds); err != nil {
		log.WithFields(logrus.Fields{"error": err}).Error("Failed to send SNMP trap")
		return
	} else {
		log.WithFields(logrus.Fields{"status": alert.Status}).Info("It's a trap!")
	}
}
