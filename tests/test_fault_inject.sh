#!/bin/bash

rand_range() {
	x=$1
	y=$2
	echo $(($x + $RANDOM % ($y-$x+1)))
}

dd_files() {
	src=$1
	dst=$2

	src_bs=$(rand_range 1 4097)
	dst_bs=$(rand_range 1 4097)

	(dd if=$src bs=$src_bs | dd of=$dst bs=$dst_bs) >/dev/null 2>&1
}

DIR=$(dirname $0)
ITERS=1000
CALLS=1000

F=/sys/kernel/debug/fault_inject/test_fault_inject
T=/sys/kernel/debug/test_fault_inject

FUNC=$(cat <<EOF
static int fault_function_\$COUNT(void)
{
	int rc = 0;

	mutex_lock(&lock);
	if (reged)
		rc = INJECT_FAULT(&inj, NULL);
	mutex_unlock(&lock);

	return rc;
}
EOF
)

CALL=$(cat <<EOF
	rc = fault_function_\$COUNT();
	if (rc)
		injected += 1;
EOF
)

rm -f $DIR/test_fault_inject.h
for i in `seq 1 $CALLS`; do
	COUNT=$i
	eval echo \"$FUNC\" >> $DIR/test_fault_inject.h
done

echo "#define CALL_FAULTS() \\" >> $DIR/test_fault_inject.h
for i in `seq 1 $CALLS`; do
	COUNT=$i
	eval echo \"$CALL \\\\\" >> $DIR/test_fault_inject.h
done
echo >> $DIR/test_fault_inject.h

# Build and insmod fault_inject
#(cd $DIR/..; make)
insmod $DIR/../fault_inject.ko >/dev/null 2>&1

# Build and insmod test_fault-inject
#(cd $DIR; make)
rmmod test_fault_inject >/dev/null 2>&1
insmod $DIR/test_fault_inject.ko >/dev/null 2>&1

echo > $T/register
echo > $T/start_thread

echo "- Create/delete group $ITERS times"
for i in `seq 1 $ITERS`; do
	echo 0 > $F/create_group
	echo 0 > $F/delete_group
done

echo "- Create group/add_faults/delete group $ITERS times"
for i in `seq 1 $ITERS`; do
	echo 0 > $F/create_group
	dd_files "$F/list_fault_points" "$F/0/add_fault_points"
	echo 0 > $F/delete_group
done

echo "- Create group/add_faults/faults_enable/delete group $ITERS times"
for i in `seq 1 $ITERS`; do
	echo 0 > $F/create_group
	dd_files "$F/list_fault_points" "$F/0/add_fault_points"
	# Errors
	echo -ENOMEM,-ENOENT > $F/0/error/errors
	echo 1 > $F/0/error/probability
	echo 1 > $F/0/error/enable
	# Delays
	echo 0:2000 > $F/0/delay/delay_us
	echo 1      > $F/0/delay/probability
	echo 1      > $F/0/delay/enable

	echo 0 > $F/delete_group
done

echo "- Create group/add_faults/faults_enable/del_faults/delete group $ITERS times"
for i in `seq 1 $ITERS`; do
	echo 0 > $F/create_group
	dd_files "$F/list_fault_points" "$F/0/add_fault_points"
	# Errors
	echo -ENOMEM,-ENOENT > $F/0/error/errors
	echo 1 > $F/0/error/probability
	echo 1 > $F/0/error/enable
	# Delays
	echo 0:2000 > $F/0/delay/delay_us
	echo 1      > $F/0/delay/probability
	echo 1      > $F/0/delay/enable

	dd_files "$F/list_fault_points" "$F/0/del_fault_points"
	echo 0 > $F/delete_group
done


echo > $T/stop_thread
echo > $T/unregister

FAULTS=`cat $T/faults_injected`
echo
echo "FAULTS INJECTED: $FAULTS"

rmmod test_fault_inject
