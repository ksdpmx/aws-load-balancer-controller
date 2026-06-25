package ingress

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"sort"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/pkg/errors"
	"sigs.k8s.io/aws-load-balancer-controller/pkg/algorithm"
	ec2model "sigs.k8s.io/aws-load-balancer-controller/pkg/model/ec2"
	elbv2model "sigs.k8s.io/aws-load-balancer-controller/pkg/model/elbv2"
)

const (
	resourceIDManagedSecurityGroup = "ManagedLBSecurityGroup"
)

func (t *defaultModelBuildTask) buildManagedSecurityGroup(ctx context.Context, listenPortConfigByPort map[int32]listenPortConfig, ipAddressType elbv2model.IPAddressType) (*ec2model.SecurityGroup, error) {
	sgSpec, err := t.buildManagedSecurityGroupSpec(ctx, listenPortConfigByPort, ipAddressType)
	if err != nil {
		return nil, err
	}

	sg := ec2model.NewSecurityGroup(t.stack, resourceIDManagedSecurityGroup, sgSpec)
	return sg, nil
}

func (t *defaultModelBuildTask) buildManagedSecurityGroups(
	ctx context.Context, listenPortConfigByPort map[int32]listenPortConfig, ipAddressType elbv2model.IPAddressType,
	enabled bool, maxRules int,
) ([]*ec2model.SecurityGroup, error) {
	// buildManagedSecurityGroupSpec manually
	baseName := t.buildManagedSecurityGroupName(ctx)
	tags, err := t.buildManagedSecurityGroupTags(ctx)
	if err != nil {
		return nil, err
	}

	ingressPermissions := t.buildManagedSecurityGroupIngressPermissions(ctx, listenPortConfigByPort, ipAddressType)
	if !enabled || len(ingressPermissions) <= maxRules {
		return []*ec2model.SecurityGroup{
			t.newManagedSecurityGroup(0, baseName, tags, ingressPermissions),
		}, nil
	}

	chunks, err := chunkIPPermissions(ingressPermissions, maxRules)
	if err != nil {
		return nil, err
	}
	var sgs []*ec2model.SecurityGroup
	for i, chunk := range chunks {
		sgs = append(sgs, t.newManagedSecurityGroup(i, baseName, tags, chunk))
	}
	return sgs, nil
}

func (t *defaultModelBuildTask) newManagedSecurityGroup(
	index int, baseName string, tags map[string]string, perms []ec2model.IPPermission,
) *ec2model.SecurityGroup {
	resourceID := resourceIDManagedSecurityGroup // "ManagedLBSecurityGroup"
	name := baseName
	if index > 0 {
		resourceID = fmt.Sprintf("%s-%d", resourceIDManagedSecurityGroup, index) // -1, -2
		name = fmt.Sprintf("%s-%d", baseName, index)
	}
	return ec2model.NewSecurityGroup(
		t.stack, resourceID, ec2model.SecurityGroupSpec{
			GroupName:   name,
			Description: "[k8s] Managed SecurityGroup for LoadBalancer",
			Tags:        tags,
			Ingress:     perms,
		},
	)
}

func chunkIPPermissions(permissions []ec2model.IPPermission, maxRules int) ([][]ec2model.IPPermission, error) {
	if maxRules < 0 {
		return nil, errors.New("maxRules cannot be negative")
	}

	sorted := make([]ec2model.IPPermission, len(permissions))
	copy(sorted, permissions)
	// stable sort
	sort.Slice(
		sorted, func(i, j int) bool {
			return ipPermissionSortKey(sorted[i]) < ipPermissionSortKey(sorted[j])
		},
	)

	// Always produce at least one chunk (one SG), aligning with the single SG behavior when there are zero rules.
	if len(sorted) == 0 {
		return [][]ec2model.IPPermission{{}}, nil
	}

	var chunks [][]ec2model.IPPermission
	for i := 0; i < len(sorted); i += maxRules {
		end := i + maxRules
		if end > len(sorted) {
			end = len(sorted)
		}
		chunks = append(chunks, sorted[i:end])
	}
	return chunks, nil
}

func ipPermissionSortKey(p ec2model.IPPermission) string {
	var fromPort, toPort int32
	if p.FromPort != nil {
		fromPort = *p.FromPort
	}
	if p.ToPort != nil {
		toPort = *p.ToPort
	}

	// sourceClass keeps v4 / v6 / prefix grouped in a fixed order.
	sourceClass := 9
	source := ""
	switch {
	case len(p.IPRanges) > 0:
		sourceClass = 0
		source = p.IPRanges[0].CIDRIP
	case len(p.IPv6Range) > 0:
		sourceClass = 1
		source = p.IPv6Range[0].CIDRIPv6
	case len(p.PrefixLists) > 0:
		sourceClass = 2
		source = p.PrefixLists[0].ListID
	}

	return fmt.Sprintf(
		"%s|%010d|%010d|%d|%s",
		p.IPProtocol, fromPort, toPort, sourceClass, source,
	)
}

func (t *defaultModelBuildTask) buildManagedSecurityGroupSpec(ctx context.Context, listenPortConfigByPort map[int32]listenPortConfig, ipAddressType elbv2model.IPAddressType) (ec2model.SecurityGroupSpec, error) {
	name := t.buildManagedSecurityGroupName(ctx)
	tags, err := t.buildManagedSecurityGroupTags(ctx)
	if err != nil {
		return ec2model.SecurityGroupSpec{}, err
	}
	ingressPermissions := t.buildManagedSecurityGroupIngressPermissions(ctx, listenPortConfigByPort, ipAddressType)
	return ec2model.SecurityGroupSpec{
		GroupName:   name,
		Description: "[k8s] Managed SecurityGroup for LoadBalancer",
		Tags:        tags,
		Ingress:     ingressPermissions,
	}, nil
}

var invalidSecurityGroupNamePtn, _ = regexp.Compile("[[:^alnum:]]")

func (t *defaultModelBuildTask) buildManagedSecurityGroupName(_ context.Context) string {
	uuidHash := sha256.New()
	_, _ = uuidHash.Write([]byte(t.clusterName))
	_, _ = uuidHash.Write([]byte(t.ingGroup.ID.String()))
	uuid := hex.EncodeToString(uuidHash.Sum(nil))

	if t.ingGroup.ID.IsExplicit() {
		payload := invalidSecurityGroupNamePtn.ReplaceAllString(t.ingGroup.ID.Name, "")
		return fmt.Sprintf("k8s-%.17s-%.10s", payload, uuid)
	}

	sanitizedNamespace := invalidSecurityGroupNamePtn.ReplaceAllString(t.ingGroup.ID.Namespace, "")
	sanitizedName := invalidSecurityGroupNamePtn.ReplaceAllString(t.ingGroup.ID.Name, "")
	return fmt.Sprintf("k8s-%.8s-%.8s-%.10s", sanitizedNamespace, sanitizedName, uuid)
}

func (t *defaultModelBuildTask) buildManagedSecurityGroupTags(_ context.Context) (map[string]string, error) {
	ingGroupTags, err := t.buildIngressGroupResourceTags(t.ingGroup.Members)
	if err != nil {
		return nil, err
	}
	return algorithm.MergeStringMap(t.defaultTags, ingGroupTags), nil
}

func (t *defaultModelBuildTask) buildManagedSecurityGroupIngressPermissions(_ context.Context, listenPortConfigByPort map[int32]listenPortConfig, ipAddressType elbv2model.IPAddressType) []ec2model.IPPermission {
	var permissions []ec2model.IPPermission
	for port, cfg := range listenPortConfigByPort {
		for _, cidr := range cfg.inboundCIDRv4s {
			permissions = append(permissions, ec2model.IPPermission{
				IPProtocol: "tcp",
				FromPort:   awssdk.Int32(port),
				ToPort:     awssdk.Int32(port),
				IPRanges: []ec2model.IPRange{
					{
						CIDRIP: cidr,
					},
				},
			})
		}
		if isIPv6Supported(ipAddressType) {
			for _, cidr := range cfg.inboundCIDRv6s {
				permissions = append(permissions, ec2model.IPPermission{
					IPProtocol: "tcp",
					FromPort:   awssdk.Int32(port),
					ToPort:     awssdk.Int32(port),
					IPv6Range: []ec2model.IPv6Range{
						{
							CIDRIPv6: cidr,
						},
					},
				})
			}
		}
		for _, prefixID := range cfg.prefixLists {
			permissions = append(permissions, ec2model.IPPermission{
				IPProtocol: "tcp",
				FromPort:   awssdk.Int32(port),
				ToPort:     awssdk.Int32(port),
				PrefixLists: []ec2model.PrefixList{
					{
						ListID: prefixID,
					},
				},
			})
		}
	}
	return permissions
}
