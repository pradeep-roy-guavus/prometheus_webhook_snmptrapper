package snmptrapper

import (
	"time"

	types "github.com/chrusty/prometheus_webhook_snmptrapper/types"

	logrus "github.com/Sirupsen/logrus"
	snmpgo "github.com/k-sone/snmpgo"
)

func addLabels(descr string, labels map[string]string) string {
    return descr + "; adaptor = " + labels["adaptor"]
}

func getTrapOID(status string, descr string) *snmpgo.Oid {
    // Essentially, this is what we have to do:
    //     trapOIDs.FiringTrap, _ = snmpgo.NewOid("1.3.6.1.3.1977.1.0.1")
    result := trapOIDs.FiringTrap
    index := 0

    /*
    oidTable := map[string][2]string{
	"No data received" : {"1.3.6.1.4.1.37140.3.0.1017", "1.3.6.1.4.1.37140.3.0.1019"},
        "Collector is crossing peak flow rate threshold" : {"1.3.6.1.4.1.37140.3.0.1032", "1.3.6.1.4.1.37140.3.0.1033"},
	"Collector is dropping too many packets" : {"1.3.6.1.4.1.37140.3.0.1022", "1.3.6.1.4.1.37140.3.0.1023"},
    }
    */

    if status != "firing" {
        index = 1
    } else {
        result = trapOIDs.RecoveryTrap
    }

    v, ok := oidMap[descr]
    if ok {
        result, _  = snmpgo.NewOid(v[index])
    }

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
