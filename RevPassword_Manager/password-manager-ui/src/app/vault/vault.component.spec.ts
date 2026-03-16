import { ComponentFixture, TestBed } from '@angular/core/testing';
import { VaultComponent } from './vault';
import { HttpClientTestingModule } from '@angular/common/http/testing';
import { VaultService } from '../core/services/vault.service';
import { ProfileService } from '../core/services/profile.service';
import { of } from 'rxjs';
import { ActivatedRoute } from '@angular/router';
import { ChangeDetectorRef } from '@angular/core';

describe('VaultComponent', () => {
  let component: VaultComponent;
  let fixture: ComponentFixture<VaultComponent>;
  let vaultServiceMock: any;
  let profileServiceMock: any;

  beforeEach(async () => {
    vaultServiceMock = {
      getAll: jasmine.createSpy('getAll').and.returnValue(of([])),
      create: jasmine.createSpy('create').and.returnValue(of({})),
      update: jasmine.createSpy('update').and.returnValue(of({})),
      delete: jasmine.createSpy('delete').and.returnValue(of({}))
    };

    profileServiceMock = {
      changePassword: jasmine.createSpy('changePassword').and.returnValue(of({}))
    };

    await TestBed.configureTestingModule({
      imports: [VaultComponent, HttpClientTestingModule],
      providers: [
        { provide: VaultService, useValue: vaultServiceMock },
        { provide: ProfileService, useValue: profileServiceMock },
        { provide: ActivatedRoute, useValue: { params: of({}) } },
        ChangeDetectorRef
      ]
    }).compileComponents();

    fixture = TestBed.createComponent(VaultComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });

  it('should load vaults on init', () => {
    expect(vaultServiceMock.getAll).toHaveBeenCalled();
  });

  it('should toggle showForm when openAdd is called', () => {
    component.openAdd();
    expect(component.showForm).toBeTrue();
    expect(component.editMode).toBeFalse();
  });

  it('should reset form after saving', () => {
    component.form = { accountName: 'Test' };
    component.resetForm();
    expect(component.form.accountName).toBe('');
  });

  it('should update strength score when password changes', () => {
    component.updateStrength('Short');
    expect(component.strengthScore).toBeLessThan(3);
    
    component.updateStrength('VeryStrongPassword123!');
    expect(component.strengthScore).toBeGreaterThan(3);
  });
});
