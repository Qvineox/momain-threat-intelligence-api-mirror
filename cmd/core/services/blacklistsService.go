package services

import (
	"bytes"
	"crypto/md5"
	"domain_threat_intelligence_api/cmd/core"
	"domain_threat_intelligence_api/cmd/core/entities"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/jackc/pgtype"
	"strconv"
	"strings"
	"sync"
)

type BlackListsServiceImpl struct {
	repo core.IBlacklistsRepo
}

func (s *BlackListsServiceImpl) RetrieveURLsByFilter(filter entities.BlacklistSearchFilter) ([]entities.BlacklistedURL, error) {
	return s.repo.SelectURLsByFilter(filter)
}

func (s *BlackListsServiceImpl) SaveURLs(urls []entities.BlacklistedURL) (int64, error) {
	if len(urls) == 0 {
		return 0, nil
	}

	// add hashes to URLs
	for i, v := range urls {
		hash := md5.Sum([]byte(v.URL))
		v.MD5 = hex.EncodeToString(hash[:])

		urls[i] = v
	}

	return s.repo.SaveURLs(urls)
}

func (s *BlackListsServiceImpl) DeleteURL(id uint64) (int64, error) {
	return s.repo.DeleteURL(id)
}

func NewBlackListsServiceImpl(repo core.IBlacklistsRepo) *BlackListsServiceImpl {
	return &BlackListsServiceImpl{repo: repo}
}

func (s *BlackListsServiceImpl) RetrieveIPsByFilter(filter entities.BlacklistSearchFilter) ([]entities.BlacklistedIP, error) {
	return s.repo.SelectIPsByFilter(filter)
}

func (s *BlackListsServiceImpl) SaveIPs(ips []entities.BlacklistedIP) (int64, error) {
	if len(ips) == 0 {
		return 0, nil
	}

	return s.repo.SaveIPs(ips)
}

func (s *BlackListsServiceImpl) DeleteIP(id uint64) (int64, error) {
	return s.repo.DeleteIP(id)
}

func (s *BlackListsServiceImpl) RetrieveDomainsByFilter(filter entities.BlacklistSearchFilter) ([]entities.BlacklistedDomain, error) {
	return s.repo.SelectDomainsByFilter(filter)
}

func (s *BlackListsServiceImpl) SaveDomains(domains []entities.BlacklistedDomain) (int64, error) {
	if len(domains) == 0 {
		return 0, nil
	}

	return s.repo.SaveDomains(domains)
}

func (s *BlackListsServiceImpl) DeleteDomain(id uint64) (int64, error) {
	return s.repo.DeleteDomain(id)
}

func (s *BlackListsServiceImpl) ImportFromSTIX2(bundles []entities.STIX2Bundle) (int64, []error) {
	var ipMap = make(map[string]*entities.BlacklistedIP)
	var domainMap = make(map[string]*entities.BlacklistedDomain)
	var urlMap = make(map[string]*entities.BlacklistedURL)

	var errors_ []error

	for bIndex, b := range bundles {
		for iIndex, object := range b.Objects {
			if object.Type != "indicator" { // skip all other object types
				continue
			}

			i, d, u, err := object.ToBlacklisted()
			if err != nil {
				errors_ = append(errors_, errors.New(fmt.Sprintf("error in bundle #%d, value #%d; error: %s", bIndex, iIndex, err.Error())))
			}

			if i != nil {
				ipMap[i.IPAddress.IPNet.String()] = i
			}

			if d != nil {
				domainMap[d.URN] = d
			}

			if u != nil {
				urlMap[u.URL] = u
			}
		}
	}

	// async saving of all host types
	var rowsTotal int64 = 0
	wg := sync.WaitGroup{}
	wg.Add(3)

	go func() {
		var ips = make([]entities.BlacklistedIP, 0, len(ipMap))
		for _, v := range ipMap {
			ips = append(ips, *v)
		}

		rows, err := s.SaveIPs(ips)
		if err != nil {
			errors_ = append(errors_, err)
		}

		rowsTotal += rows
		wg.Done()
	}()

	go func() {
		var urls = make([]entities.BlacklistedURL, 0, len(urlMap))
		for _, v := range urlMap {
			urls = append(urls, *v)
		}

		rows, err := s.SaveURLs(urls)
		if err != nil {
			errors_ = append(errors_, err)
		}

		rowsTotal += rows
		wg.Done()
	}()

	go func() {
		var domains = make([]entities.BlacklistedDomain, 0, len(domainMap))
		for _, v := range domainMap {
			domains = append(domains, *v)
		}

		rows, err := s.SaveDomains(domains)
		if err != nil {
			errors_ = append(errors_, err)
		}

		rowsTotal += rows
		wg.Done()
	}()

	wg.Wait()

	return rowsTotal, errors_
}

func (s *BlackListsServiceImpl) ImportFromCSV(data [][]string) (int64, []error) {
	var ipMap = make(map[string]*entities.BlacklistedIP)
	var domainMap = make(map[string]*entities.BlacklistedDomain)
	var urlMap = make(map[string]*entities.BlacklistedURL)

	var errors_ []error

	// read all lines, remove header
	for _, r := range data[1:] {
		t, v, s_, c := r[0], r[1], r[6], r[9]

		var source uint64
		switch s_ {
		case "Vendor-Kaspersky":
			source = entities.SourceKaspersky
		case "Vendor-DRWEB":
			source = entities.SourceDrWeb
		case "FinCERT":
			source = entities.SourceFinCERT
		default:
			source = entities.SourceUnknown
		}

		comment := strings.Trim(c, "\"")

		switch t {
		case "Domain":
			domainMap[v] = &entities.BlacklistedDomain{
				URN:         v,
				Description: comment,
				SourceID:    source,
			}
		case "IP-addres":
			ip := pgtype.Inet{}
			err := ip.Set(v)
			if err != nil {
				errors_ = append(errors_, err)
				continue
			}

			ipMap[ip.IPNet.String()] = &entities.BlacklistedIP{
				IPAddress:   ip,
				Description: comment,
				SourceID:    source,
			}
		case "URL":
			urlMap[v] = &entities.BlacklistedURL{
				URL:         v,
				Description: comment,
				SourceID:    source,
			}
		}
	}

	// async saving of all host types
	var rowsTotal int64 = 0
	wg := sync.WaitGroup{}
	wg.Add(3)

	go func() {
		var ips = make([]entities.BlacklistedIP, 0, len(ipMap))
		for _, v := range ipMap {
			ips = append(ips, *v)
		}

		rows, err := s.SaveIPs(ips)
		if err != nil {
			errors_ = append(errors_, err)
		}

		rowsTotal += rows
		wg.Done()
	}()

	go func() {
		var urls = make([]entities.BlacklistedURL, 0, len(urlMap))
		for _, v := range urlMap {
			urls = append(urls, *v)
		}

		rows, err := s.SaveURLs(urls)
		if err != nil {
			errors_ = append(errors_, err)
		}

		rowsTotal += rows
		wg.Done()
	}()

	go func() {
		var domains = make([]entities.BlacklistedDomain, 0, len(domainMap))
		for _, v := range domainMap {
			domains = append(domains, *v)
		}

		rows, err := s.SaveDomains(domains)
		if err != nil {
			errors_ = append(errors_, err)
		}

		rowsTotal += rows
		wg.Done()
	}()

	wg.Wait()

	return rowsTotal, errors_
}

func (s *BlackListsServiceImpl) ExportToJSON(filter entities.BlacklistExportFilter) ([]byte, error) {
	bundle, err := s.getAllBlacklistedByFilter(filter)
	if err != nil {
		return nil, err
	}

	bytes_, err := json.Marshal(bundle)
	if err != nil {
		return nil, err
	}

	return bytes_, nil
}

func (s *BlackListsServiceImpl) ExportToCSV(filter entities.BlacklistExportFilter) ([]byte, error) {
	bundle, err := s.getAllBlacklistedByFilter(filter)
	if err != nil {
		return nil, err
	}

	var lines [][]string

	lines = append(lines, []string{"ID", "Identity", "Source", "CreatedAt", "UpdatedAt"})

	for _, v := range bundle.IPs {
		lines = append(lines, []string{strconv.Itoa(int(v.ID)), v.IPAddress.IPNet.String(), v.Source.Name, v.CreatedAt.Format("02.01.2006"), v.UpdatedAt.Format("02.01.2006")})
	}

	for _, v := range bundle.Domains {
		lines = append(lines, []string{strconv.Itoa(int(v.ID)), v.URN, v.Source.Name, v.CreatedAt.Format("02.01.2006"), v.UpdatedAt.Format("02.01.2006")})
	}

	for _, v := range bundle.URLs {
		lines = append(lines, []string{strconv.Itoa(int(v.ID)), v.URL, v.Source.Name, v.CreatedAt.Format("02.01.2006"), v.UpdatedAt.Format("02.01.2006")})
	}

	var buf bytes.Buffer

	w := csv.NewWriter(&buf)
	err = w.WriteAll(lines)
	if err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

func (s *BlackListsServiceImpl) getAllBlacklistedByFilter(filter entities.BlacklistExportFilter) (BlacklistedBundle, error) {
	var bundle BlacklistedBundle

	var err error
	wg := &sync.WaitGroup{}
	wg.Add(3)

	go func() {
		bundle.URLs, err = s.RetrieveURLsByFilter(entities.BlacklistSearchFilter{
			SourceIDs:     filter.SourceIDs,
			CreatedAfter:  filter.CreatedAfter,
			CreatedBefore: filter.CreatedBefore,
		})

		wg.Done()
	}()

	go func() {
		bundle.Domains, err = s.RetrieveDomainsByFilter(entities.BlacklistSearchFilter{
			SourceIDs:     filter.SourceIDs,
			CreatedAfter:  filter.CreatedAfter,
			CreatedBefore: filter.CreatedBefore,
		})

		wg.Done()
	}()

	go func() {
		bundle.IPs, err = s.RetrieveIPsByFilter(entities.BlacklistSearchFilter{
			SourceIDs:     filter.SourceIDs,
			CreatedAfter:  filter.CreatedAfter,
			CreatedBefore: filter.CreatedBefore,
		})

		wg.Done()
	}()

	wg.Wait()
	return bundle, err
}

func (s *BlackListsServiceImpl) RetrieveStatistics() (int64, int64, int64) {
	return s.repo.CountStatistics()
}

type BlacklistedBundle struct {
	IPs     []entities.BlacklistedIP     `json:"blacklisted_ip_addresses"`
	Domains []entities.BlacklistedDomain `json:"blacklisted_domains"`
	URLs    []entities.BlacklistedURL    `json:"blacklisted_urls"`
}
