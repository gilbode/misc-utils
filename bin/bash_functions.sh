#!/bin/sh

function oci_compartment_id() {
    if [ $# -ne 1 ] ; then
        echo "usage: ${FUNCNAME[0]} compartment_name"
    fi
    local _compartment_name="$1"
    local _compartment_ids=$(oci --raw-output --query "data[?name=='${_compartment_name}' && \"lifecycle-state\"=='ACTIVE'].id" iam compartment list --access-level ANY  --compartment-id-in-subtree true --all 2>/dev/null)

    if [ $? -ne 0 ] || [ "${_compartment_ids}" == "" ] ; then
        echo "Compartment ${_compartment_name} not found"
        return 1
    fi
    echo "${_compartment_ids}" | jq -e 'if type == "array" and length != 1 then false else true end' > /dev/null
    if [ $? -ne 0 ] ; then
        echo "More than one compartment named ${_compartment_name}"
        return 1
    fi

    echo "${_compartment_ids}" | jq -r '.[0]'

    return 0
}
