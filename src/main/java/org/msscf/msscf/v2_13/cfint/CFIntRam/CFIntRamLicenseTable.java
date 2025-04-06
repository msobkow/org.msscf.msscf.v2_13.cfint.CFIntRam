
// Description: Java 11 in-memory RAM DbIO implementation for License.

/*
 *	org.msscf.msscf.CFInt
 *
 *	Copyright (c) 2020 Mark Stephen Sobkow
 *	
 *	MSS Code Factory CFInt 2.13 Internet Essentials
 *	
 *	Copyright 2020-2021 Mark Stephen Sobkow mark.sobkow@gmail.com
 *	
 *	Licensed under the Apache License, Version 2.0 (the "License");
 *	you may not use this file except in compliance with the License.
 *	You may obtain a copy of the License at
 *	
 *	http://www.apache.org/licenses/LICENSE-2.0
 *	
 *	Unless required by applicable law or agreed to in writing, software
 *	distributed under the License is distributed on an "AS IS" BASIS,
 *	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *	See the License for the specific language governing permissions and
 *	limitations under the License.
 *
 *	Manufactured by MSS Code Factory 2.12
 */

package org.msscf.msscf.v2_13.cfint.CFIntRam;

import java.math.*;
import java.sql.*;
import java.text.*;
import java.util.*;
import org.apache.commons.codec.binary.Base64;
import org.msscf.msscf.v2_13.cflib.CFLib.*;
import org.msscf.msscf.v2_13.cfsec.CFSec.*;
import org.msscf.msscf.v2_13.cfint.CFInt.*;
import org.msscf.msscf.v2_13.cfint.CFIntObj.*;
import org.msscf.msscf.v2_13.cfsec.CFSecObj.*;
import org.msscf.msscf.v2_13.cfint.CFIntObj.*;

/*
 *	CFIntRamLicenseTable in-memory RAM DbIO implementation
 *	for License.
 */
public class CFIntRamLicenseTable
	implements ICFIntLicenseTable
{
	private ICFIntSchema schema;
	private Map< CFIntLicensePKey,
				CFIntLicenseBuff > dictByPKey
		= new HashMap< CFIntLicensePKey,
				CFIntLicenseBuff >();
	private Map< CFIntLicenseByLicnTenantIdxKey,
				Map< CFIntLicensePKey,
					CFIntLicenseBuff >> dictByLicnTenantIdx
		= new HashMap< CFIntLicenseByLicnTenantIdxKey,
				Map< CFIntLicensePKey,
					CFIntLicenseBuff >>();
	private Map< CFIntLicenseByDomainIdxKey,
				Map< CFIntLicensePKey,
					CFIntLicenseBuff >> dictByDomainIdx
		= new HashMap< CFIntLicenseByDomainIdxKey,
				Map< CFIntLicensePKey,
					CFIntLicenseBuff >>();
	private Map< CFIntLicenseByUNameIdxKey,
			CFIntLicenseBuff > dictByUNameIdx
		= new HashMap< CFIntLicenseByUNameIdxKey,
			CFIntLicenseBuff >();

	public CFIntRamLicenseTable( ICFIntSchema argSchema ) {
		schema = argSchema;
	}

	public void createLicense( CFSecAuthorization Authorization,
		CFIntLicenseBuff Buff )
	{
		final String S_ProcName = "createLicense";
		CFIntLicensePKey pkey = schema.getFactoryLicense().newPKey();
		pkey.setRequiredTenantId( Buff.getRequiredTenantId() );
		pkey.setRequiredId( ((CFIntRamTenantTable)schema.getTableTenant()).nextLicenseIdGen( Authorization,
			Buff.getRequiredTenantId() ) );
		Buff.setRequiredTenantId( pkey.getRequiredTenantId() );
		Buff.setRequiredId( pkey.getRequiredId() );
		CFIntLicenseByLicnTenantIdxKey keyLicnTenantIdx = schema.getFactoryLicense().newLicnTenantIdxKey();
		keyLicnTenantIdx.setRequiredTenantId( Buff.getRequiredTenantId() );

		CFIntLicenseByDomainIdxKey keyDomainIdx = schema.getFactoryLicense().newDomainIdxKey();
		keyDomainIdx.setRequiredTenantId( Buff.getRequiredTenantId() );
		keyDomainIdx.setRequiredTopDomainId( Buff.getRequiredTopDomainId() );

		CFIntLicenseByUNameIdxKey keyUNameIdx = schema.getFactoryLicense().newUNameIdxKey();
		keyUNameIdx.setRequiredTenantId( Buff.getRequiredTenantId() );
		keyUNameIdx.setRequiredTopDomainId( Buff.getRequiredTopDomainId() );
		keyUNameIdx.setRequiredName( Buff.getRequiredName() );

		// Validate unique indexes

		if( dictByPKey.containsKey( pkey ) ) {
			throw new CFLibPrimaryKeyNotNewException( getClass(), S_ProcName, pkey );
		}

		if( dictByUNameIdx.containsKey( keyUNameIdx ) ) {
			throw new CFLibUniqueIndexViolationException( getClass(),
				S_ProcName,
				"LicenseUNameIdx",
				keyUNameIdx );
		}

		// Validate foreign keys

		{
			boolean allNull = true;
			allNull = false;
			if( ! allNull ) {
				if( null == schema.getTableTenant().readDerivedByIdIdx( Authorization,
						Buff.getRequiredTenantId() ) )
				{
					throw new CFLibUnresolvedRelationException( getClass(),
						S_ProcName,
						"Owner",
						"Owner",
						"Tenant",
						null );
				}
			}
		}

		{
			boolean allNull = true;
			allNull = false;
			allNull = false;
			if( ! allNull ) {
				if( null == schema.getTableTopDomain().readDerivedByIdIdx( Authorization,
						Buff.getRequiredTenantId(),
						Buff.getRequiredTopDomainId() ) )
				{
					throw new CFLibUnresolvedRelationException( getClass(),
						S_ProcName,
						"Container",
						"TopDomain",
						"TopDomain",
						null );
				}
			}
		}

		// Proceed with adding the new record

		dictByPKey.put( pkey, Buff );

		Map< CFIntLicensePKey, CFIntLicenseBuff > subdictLicnTenantIdx;
		if( dictByLicnTenantIdx.containsKey( keyLicnTenantIdx ) ) {
			subdictLicnTenantIdx = dictByLicnTenantIdx.get( keyLicnTenantIdx );
		}
		else {
			subdictLicnTenantIdx = new HashMap< CFIntLicensePKey, CFIntLicenseBuff >();
			dictByLicnTenantIdx.put( keyLicnTenantIdx, subdictLicnTenantIdx );
		}
		subdictLicnTenantIdx.put( pkey, Buff );

		Map< CFIntLicensePKey, CFIntLicenseBuff > subdictDomainIdx;
		if( dictByDomainIdx.containsKey( keyDomainIdx ) ) {
			subdictDomainIdx = dictByDomainIdx.get( keyDomainIdx );
		}
		else {
			subdictDomainIdx = new HashMap< CFIntLicensePKey, CFIntLicenseBuff >();
			dictByDomainIdx.put( keyDomainIdx, subdictDomainIdx );
		}
		subdictDomainIdx.put( pkey, Buff );

		dictByUNameIdx.put( keyUNameIdx, Buff );

	}

	public CFIntLicenseBuff readDerived( CFSecAuthorization Authorization,
		CFIntLicensePKey PKey )
	{
		final String S_ProcName = "CFIntRamLicense.readDerived";
		CFIntLicensePKey key = schema.getFactoryLicense().newPKey();
		key.setRequiredTenantId( PKey.getRequiredTenantId() );
		key.setRequiredId( PKey.getRequiredId() );
		CFIntLicenseBuff buff;
		if( dictByPKey.containsKey( key ) ) {
			buff = dictByPKey.get( key );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	public CFIntLicenseBuff lockDerived( CFSecAuthorization Authorization,
		CFIntLicensePKey PKey )
	{
		final String S_ProcName = "CFIntRamLicense.readDerived";
		CFIntLicensePKey key = schema.getFactoryLicense().newPKey();
		key.setRequiredTenantId( PKey.getRequiredTenantId() );
		key.setRequiredId( PKey.getRequiredId() );
		CFIntLicenseBuff buff;
		if( dictByPKey.containsKey( key ) ) {
			buff = dictByPKey.get( key );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	public CFIntLicenseBuff[] readAllDerived( CFSecAuthorization Authorization ) {
		final String S_ProcName = "CFIntRamLicense.readAllDerived";
		CFIntLicenseBuff[] retList = new CFIntLicenseBuff[ dictByPKey.values().size() ];
		Iterator< CFIntLicenseBuff > iter = dictByPKey.values().iterator();
		int idx = 0;
		while( iter.hasNext() ) {
			retList[ idx++ ] = iter.next();
		}
		return( retList );
	}

	public CFIntLicenseBuff[] readDerivedByLicnTenantIdx( CFSecAuthorization Authorization,
		long TenantId )
	{
		final String S_ProcName = "CFIntRamLicense.readDerivedByLicnTenantIdx";
		CFIntLicenseByLicnTenantIdxKey key = schema.getFactoryLicense().newLicnTenantIdxKey();
		key.setRequiredTenantId( TenantId );

		CFIntLicenseBuff[] recArray;
		if( dictByLicnTenantIdx.containsKey( key ) ) {
			Map< CFIntLicensePKey, CFIntLicenseBuff > subdictLicnTenantIdx
				= dictByLicnTenantIdx.get( key );
			recArray = new CFIntLicenseBuff[ subdictLicnTenantIdx.size() ];
			Iterator< CFIntLicenseBuff > iter = subdictLicnTenantIdx.values().iterator();
			int idx = 0;
			while( iter.hasNext() ) {
				recArray[ idx++ ] = iter.next();
			}
		}
		else {
			Map< CFIntLicensePKey, CFIntLicenseBuff > subdictLicnTenantIdx
				= new HashMap< CFIntLicensePKey, CFIntLicenseBuff >();
			dictByLicnTenantIdx.put( key, subdictLicnTenantIdx );
			recArray = new CFIntLicenseBuff[0];
		}
		return( recArray );
	}

	public CFIntLicenseBuff[] readDerivedByDomainIdx( CFSecAuthorization Authorization,
		long TenantId,
		long TopDomainId )
	{
		final String S_ProcName = "CFIntRamLicense.readDerivedByDomainIdx";
		CFIntLicenseByDomainIdxKey key = schema.getFactoryLicense().newDomainIdxKey();
		key.setRequiredTenantId( TenantId );
		key.setRequiredTopDomainId( TopDomainId );

		CFIntLicenseBuff[] recArray;
		if( dictByDomainIdx.containsKey( key ) ) {
			Map< CFIntLicensePKey, CFIntLicenseBuff > subdictDomainIdx
				= dictByDomainIdx.get( key );
			recArray = new CFIntLicenseBuff[ subdictDomainIdx.size() ];
			Iterator< CFIntLicenseBuff > iter = subdictDomainIdx.values().iterator();
			int idx = 0;
			while( iter.hasNext() ) {
				recArray[ idx++ ] = iter.next();
			}
		}
		else {
			Map< CFIntLicensePKey, CFIntLicenseBuff > subdictDomainIdx
				= new HashMap< CFIntLicensePKey, CFIntLicenseBuff >();
			dictByDomainIdx.put( key, subdictDomainIdx );
			recArray = new CFIntLicenseBuff[0];
		}
		return( recArray );
	}

	public CFIntLicenseBuff readDerivedByUNameIdx( CFSecAuthorization Authorization,
		long TenantId,
		long TopDomainId,
		String Name )
	{
		final String S_ProcName = "CFIntRamLicense.readDerivedByUNameIdx";
		CFIntLicenseByUNameIdxKey key = schema.getFactoryLicense().newUNameIdxKey();
		key.setRequiredTenantId( TenantId );
		key.setRequiredTopDomainId( TopDomainId );
		key.setRequiredName( Name );

		CFIntLicenseBuff buff;
		if( dictByUNameIdx.containsKey( key ) ) {
			buff = dictByUNameIdx.get( key );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	public CFIntLicenseBuff readDerivedByIdIdx( CFSecAuthorization Authorization,
		long TenantId,
		long Id )
	{
		final String S_ProcName = "CFIntRamLicense.readDerivedByIdIdx() ";
		CFIntLicensePKey key = schema.getFactoryLicense().newPKey();
		key.setRequiredTenantId( TenantId );
		key.setRequiredId( Id );

		CFIntLicenseBuff buff;
		if( dictByPKey.containsKey( key ) ) {
			buff = dictByPKey.get( key );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	public CFIntLicenseBuff readBuff( CFSecAuthorization Authorization,
		CFIntLicensePKey PKey )
	{
		final String S_ProcName = "CFIntRamLicense.readBuff";
		CFIntLicenseBuff buff = readDerived( Authorization, PKey );
		if( ( buff != null ) && ( ! buff.getClassCode().equals( "a101" ) ) ) {
			buff = null;
		}
		return( buff );
	}

	public CFIntLicenseBuff lockBuff( CFSecAuthorization Authorization,
		CFIntLicensePKey PKey )
	{
		final String S_ProcName = "lockBuff";
		CFIntLicenseBuff buff = readDerived( Authorization, PKey );
		if( ( buff != null ) && ( ! buff.getClassCode().equals( "a101" ) ) ) {
			buff = null;
		}
		return( buff );
	}

	public CFIntLicenseBuff[] readAllBuff( CFSecAuthorization Authorization )
	{
		final String S_ProcName = "CFIntRamLicense.readAllBuff";
		CFIntLicenseBuff buff;
		ArrayList<CFIntLicenseBuff> filteredList = new ArrayList<CFIntLicenseBuff>();
		CFIntLicenseBuff[] buffList = readAllDerived( Authorization );
		for( int idx = 0; idx < buffList.length; idx ++ ) {
			buff = buffList[idx];
			if( ( buff != null ) && buff.getClassCode().equals( "a101" ) ) {
				filteredList.add( buff );
			}
		}
		return( filteredList.toArray( new CFIntLicenseBuff[0] ) );
	}

	public CFIntLicenseBuff readBuffByIdIdx( CFSecAuthorization Authorization,
		long TenantId,
		long Id )
	{
		final String S_ProcName = "CFIntRamLicense.readBuffByIdIdx() ";
		CFIntLicenseBuff buff = readDerivedByIdIdx( Authorization,
			TenantId,
			Id );
		if( ( buff != null ) && buff.getClassCode().equals( "a101" ) ) {
			return( (CFIntLicenseBuff)buff );
		}
		else {
			return( null );
		}
	}

	public CFIntLicenseBuff[] readBuffByLicnTenantIdx( CFSecAuthorization Authorization,
		long TenantId )
	{
		final String S_ProcName = "CFIntRamLicense.readBuffByLicnTenantIdx() ";
		CFIntLicenseBuff buff;
		ArrayList<CFIntLicenseBuff> filteredList = new ArrayList<CFIntLicenseBuff>();
		CFIntLicenseBuff[] buffList = readDerivedByLicnTenantIdx( Authorization,
			TenantId );
		for( int idx = 0; idx < buffList.length; idx ++ ) {
			buff = buffList[idx];
			if( ( buff != null ) && buff.getClassCode().equals( "a101" ) ) {
				filteredList.add( (CFIntLicenseBuff)buff );
			}
		}
		return( filteredList.toArray( new CFIntLicenseBuff[0] ) );
	}

	public CFIntLicenseBuff[] readBuffByDomainIdx( CFSecAuthorization Authorization,
		long TenantId,
		long TopDomainId )
	{
		final String S_ProcName = "CFIntRamLicense.readBuffByDomainIdx() ";
		CFIntLicenseBuff buff;
		ArrayList<CFIntLicenseBuff> filteredList = new ArrayList<CFIntLicenseBuff>();
		CFIntLicenseBuff[] buffList = readDerivedByDomainIdx( Authorization,
			TenantId,
			TopDomainId );
		for( int idx = 0; idx < buffList.length; idx ++ ) {
			buff = buffList[idx];
			if( ( buff != null ) && buff.getClassCode().equals( "a101" ) ) {
				filteredList.add( (CFIntLicenseBuff)buff );
			}
		}
		return( filteredList.toArray( new CFIntLicenseBuff[0] ) );
	}

	public CFIntLicenseBuff readBuffByUNameIdx( CFSecAuthorization Authorization,
		long TenantId,
		long TopDomainId,
		String Name )
	{
		final String S_ProcName = "CFIntRamLicense.readBuffByUNameIdx() ";
		CFIntLicenseBuff buff = readDerivedByUNameIdx( Authorization,
			TenantId,
			TopDomainId,
			Name );
		if( ( buff != null ) && buff.getClassCode().equals( "a101" ) ) {
			return( (CFIntLicenseBuff)buff );
		}
		else {
			return( null );
		}
	}

	public void updateLicense( CFSecAuthorization Authorization,
		CFIntLicenseBuff Buff )
	{
		CFIntLicensePKey pkey = schema.getFactoryLicense().newPKey();
		pkey.setRequiredTenantId( Buff.getRequiredTenantId() );
		pkey.setRequiredId( Buff.getRequiredId() );
		CFIntLicenseBuff existing = dictByPKey.get( pkey );
		if( existing == null ) {
			throw new CFLibStaleCacheDetectedException( getClass(),
				"updateLicense",
				"Existing record not found",
				"License",
				pkey );
		}
		if( existing.getRequiredRevision() != Buff.getRequiredRevision() ) {
			throw new CFLibCollisionDetectedException( getClass(),
				"updateLicense",
				pkey );
		}
		Buff.setRequiredRevision( Buff.getRequiredRevision() + 1 );
		CFIntLicenseByLicnTenantIdxKey existingKeyLicnTenantIdx = schema.getFactoryLicense().newLicnTenantIdxKey();
		existingKeyLicnTenantIdx.setRequiredTenantId( existing.getRequiredTenantId() );

		CFIntLicenseByLicnTenantIdxKey newKeyLicnTenantIdx = schema.getFactoryLicense().newLicnTenantIdxKey();
		newKeyLicnTenantIdx.setRequiredTenantId( Buff.getRequiredTenantId() );

		CFIntLicenseByDomainIdxKey existingKeyDomainIdx = schema.getFactoryLicense().newDomainIdxKey();
		existingKeyDomainIdx.setRequiredTenantId( existing.getRequiredTenantId() );
		existingKeyDomainIdx.setRequiredTopDomainId( existing.getRequiredTopDomainId() );

		CFIntLicenseByDomainIdxKey newKeyDomainIdx = schema.getFactoryLicense().newDomainIdxKey();
		newKeyDomainIdx.setRequiredTenantId( Buff.getRequiredTenantId() );
		newKeyDomainIdx.setRequiredTopDomainId( Buff.getRequiredTopDomainId() );

		CFIntLicenseByUNameIdxKey existingKeyUNameIdx = schema.getFactoryLicense().newUNameIdxKey();
		existingKeyUNameIdx.setRequiredTenantId( existing.getRequiredTenantId() );
		existingKeyUNameIdx.setRequiredTopDomainId( existing.getRequiredTopDomainId() );
		existingKeyUNameIdx.setRequiredName( existing.getRequiredName() );

		CFIntLicenseByUNameIdxKey newKeyUNameIdx = schema.getFactoryLicense().newUNameIdxKey();
		newKeyUNameIdx.setRequiredTenantId( Buff.getRequiredTenantId() );
		newKeyUNameIdx.setRequiredTopDomainId( Buff.getRequiredTopDomainId() );
		newKeyUNameIdx.setRequiredName( Buff.getRequiredName() );

		// Check unique indexes

		if( ! existingKeyUNameIdx.equals( newKeyUNameIdx ) ) {
			if( dictByUNameIdx.containsKey( newKeyUNameIdx ) ) {
				throw new CFLibUniqueIndexViolationException( getClass(),
					"updateLicense",
					"LicenseUNameIdx",
					newKeyUNameIdx );
			}
		}

		// Validate foreign keys

		{
			boolean allNull = true;

			if( allNull ) {
				if( null == schema.getTableTenant().readDerivedByIdIdx( Authorization,
						Buff.getRequiredTenantId() ) )
				{
					throw new CFLibUnresolvedRelationException( getClass(),
						"updateLicense",
						"Owner",
						"Owner",
						"Tenant",
						null );
				}
			}
		}

		{
			boolean allNull = true;

			if( allNull ) {
				if( null == schema.getTableTopDomain().readDerivedByIdIdx( Authorization,
						Buff.getRequiredTenantId(),
						Buff.getRequiredTopDomainId() ) )
				{
					throw new CFLibUnresolvedRelationException( getClass(),
						"updateLicense",
						"Container",
						"TopDomain",
						"TopDomain",
						null );
				}
			}
		}

		// Update is valid

		Map< CFIntLicensePKey, CFIntLicenseBuff > subdict;

		dictByPKey.remove( pkey );
		dictByPKey.put( pkey, Buff );

		subdict = dictByLicnTenantIdx.get( existingKeyLicnTenantIdx );
		if( subdict != null ) {
			subdict.remove( pkey );
		}
		if( dictByLicnTenantIdx.containsKey( newKeyLicnTenantIdx ) ) {
			subdict = dictByLicnTenantIdx.get( newKeyLicnTenantIdx );
		}
		else {
			subdict = new HashMap< CFIntLicensePKey, CFIntLicenseBuff >();
			dictByLicnTenantIdx.put( newKeyLicnTenantIdx, subdict );
		}
		subdict.put( pkey, Buff );

		subdict = dictByDomainIdx.get( existingKeyDomainIdx );
		if( subdict != null ) {
			subdict.remove( pkey );
		}
		if( dictByDomainIdx.containsKey( newKeyDomainIdx ) ) {
			subdict = dictByDomainIdx.get( newKeyDomainIdx );
		}
		else {
			subdict = new HashMap< CFIntLicensePKey, CFIntLicenseBuff >();
			dictByDomainIdx.put( newKeyDomainIdx, subdict );
		}
		subdict.put( pkey, Buff );

		dictByUNameIdx.remove( existingKeyUNameIdx );
		dictByUNameIdx.put( newKeyUNameIdx, Buff );

	}

	public void deleteLicense( CFSecAuthorization Authorization,
		CFIntLicenseBuff Buff )
	{
		final String S_ProcName = "CFIntRamLicenseTable.deleteLicense() ";
		String classCode;
		CFIntLicensePKey pkey = schema.getFactoryLicense().newPKey();
		pkey.setRequiredTenantId( Buff.getRequiredTenantId() );
		pkey.setRequiredId( Buff.getRequiredId() );
		CFIntLicenseBuff existing = dictByPKey.get( pkey );
		if( existing == null ) {
			return;
		}
		if( existing.getRequiredRevision() != Buff.getRequiredRevision() )
		{
			throw new CFLibCollisionDetectedException( getClass(),
				"deleteLicense",
				pkey );
		}
		CFIntLicenseByLicnTenantIdxKey keyLicnTenantIdx = schema.getFactoryLicense().newLicnTenantIdxKey();
		keyLicnTenantIdx.setRequiredTenantId( existing.getRequiredTenantId() );

		CFIntLicenseByDomainIdxKey keyDomainIdx = schema.getFactoryLicense().newDomainIdxKey();
		keyDomainIdx.setRequiredTenantId( existing.getRequiredTenantId() );
		keyDomainIdx.setRequiredTopDomainId( existing.getRequiredTopDomainId() );

		CFIntLicenseByUNameIdxKey keyUNameIdx = schema.getFactoryLicense().newUNameIdxKey();
		keyUNameIdx.setRequiredTenantId( existing.getRequiredTenantId() );
		keyUNameIdx.setRequiredTopDomainId( existing.getRequiredTopDomainId() );
		keyUNameIdx.setRequiredName( existing.getRequiredName() );

		// Validate reverse foreign keys

		// Delete is valid
		Map< CFIntLicensePKey, CFIntLicenseBuff > subdict;

		dictByPKey.remove( pkey );

		subdict = dictByLicnTenantIdx.get( keyLicnTenantIdx );
		subdict.remove( pkey );

		subdict = dictByDomainIdx.get( keyDomainIdx );
		subdict.remove( pkey );

		dictByUNameIdx.remove( keyUNameIdx );

	}
	public void deleteLicenseByIdIdx( CFSecAuthorization Authorization,
		long argTenantId,
		long argId )
	{
		CFIntLicensePKey key = schema.getFactoryLicense().newPKey();
		key.setRequiredTenantId( argTenantId );
		key.setRequiredId( argId );
		deleteLicenseByIdIdx( Authorization, key );
	}

	public void deleteLicenseByIdIdx( CFSecAuthorization Authorization,
		CFIntLicensePKey argKey )
	{
		boolean anyNotNull = false;
		anyNotNull = true;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		CFIntLicenseBuff cur;
		LinkedList<CFIntLicenseBuff> matchSet = new LinkedList<CFIntLicenseBuff>();
		Iterator<CFIntLicenseBuff> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFIntLicenseBuff> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = schema.getTableLicense().readDerivedByIdIdx( Authorization,
				cur.getRequiredTenantId(),
				cur.getRequiredId() );
			deleteLicense( Authorization, cur );
		}
	}

	public void deleteLicenseByLicnTenantIdx( CFSecAuthorization Authorization,
		long argTenantId )
	{
		CFIntLicenseByLicnTenantIdxKey key = schema.getFactoryLicense().newLicnTenantIdxKey();
		key.setRequiredTenantId( argTenantId );
		deleteLicenseByLicnTenantIdx( Authorization, key );
	}

	public void deleteLicenseByLicnTenantIdx( CFSecAuthorization Authorization,
		CFIntLicenseByLicnTenantIdxKey argKey )
	{
		CFIntLicenseBuff cur;
		boolean anyNotNull = false;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		LinkedList<CFIntLicenseBuff> matchSet = new LinkedList<CFIntLicenseBuff>();
		Iterator<CFIntLicenseBuff> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFIntLicenseBuff> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = schema.getTableLicense().readDerivedByIdIdx( Authorization,
				cur.getRequiredTenantId(),
				cur.getRequiredId() );
			deleteLicense( Authorization, cur );
		}
	}

	public void deleteLicenseByDomainIdx( CFSecAuthorization Authorization,
		long argTenantId,
		long argTopDomainId )
	{
		CFIntLicenseByDomainIdxKey key = schema.getFactoryLicense().newDomainIdxKey();
		key.setRequiredTenantId( argTenantId );
		key.setRequiredTopDomainId( argTopDomainId );
		deleteLicenseByDomainIdx( Authorization, key );
	}

	public void deleteLicenseByDomainIdx( CFSecAuthorization Authorization,
		CFIntLicenseByDomainIdxKey argKey )
	{
		CFIntLicenseBuff cur;
		boolean anyNotNull = false;
		anyNotNull = true;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		LinkedList<CFIntLicenseBuff> matchSet = new LinkedList<CFIntLicenseBuff>();
		Iterator<CFIntLicenseBuff> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFIntLicenseBuff> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = schema.getTableLicense().readDerivedByIdIdx( Authorization,
				cur.getRequiredTenantId(),
				cur.getRequiredId() );
			deleteLicense( Authorization, cur );
		}
	}

	public void deleteLicenseByUNameIdx( CFSecAuthorization Authorization,
		long argTenantId,
		long argTopDomainId,
		String argName )
	{
		CFIntLicenseByUNameIdxKey key = schema.getFactoryLicense().newUNameIdxKey();
		key.setRequiredTenantId( argTenantId );
		key.setRequiredTopDomainId( argTopDomainId );
		key.setRequiredName( argName );
		deleteLicenseByUNameIdx( Authorization, key );
	}

	public void deleteLicenseByUNameIdx( CFSecAuthorization Authorization,
		CFIntLicenseByUNameIdxKey argKey )
	{
		CFIntLicenseBuff cur;
		boolean anyNotNull = false;
		anyNotNull = true;
		anyNotNull = true;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		LinkedList<CFIntLicenseBuff> matchSet = new LinkedList<CFIntLicenseBuff>();
		Iterator<CFIntLicenseBuff> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFIntLicenseBuff> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = schema.getTableLicense().readDerivedByIdIdx( Authorization,
				cur.getRequiredTenantId(),
				cur.getRequiredId() );
			deleteLicense( Authorization, cur );
		}
	}

	public void releasePreparedStatements() {
	}
}
